{
  description = "Arkade emulator, and its AWS Nitro Enclave image";

  inputs = {
    # Pinned to a revision carrying Go >= 1.26.6, which go.mod requires. nixpkgs-unstable
    # is still on 1.26.5 and the Nix sandbox cannot download a newer toolchain, so the
    # build would fail there.
    nixpkgs.url = "github:NixOS/nixpkgs/4651bb1e93b161a60975279b6ca8381de59d9a9c";

    # master, not a branch ref.
    #
    # TODO: Update this to a release tag.
    enclave.url = "github:ArkLabsHQ/enclave/a666c4f890dd06acd7c586ec713444c2a22cfd07";
  };

  outputs =
    { nixpkgs, enclave, ... }:
    let
      # Nitro Enclaves runs on x86_64 here. aarch64 EIFs build and measure correctly but
      # cannot boot: blobs/aarch64/Image.config omits CONFIG_PTP_1588_CLOCK_KVM, so
      # /dev/ptp0 never appears and the runtime's mandatory clock sync fails.
      # See ArkLabsHQ/enclave#158.
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      lib = pkgs.lib;

      version = "0.0.8-rc.0";

      # PCR0 covers every byte of the source that reaches the build, so a plain
      # `src = ./.` makes the measurement move when a README, a CI file or .gitignore
      # changes — each of which would otherwise force a migration for no reason.
      # Verified: editing .gitignore alone moved PCR0 from dc1faa48 to a645facf, and
      # reverting it restored dc1faa48 exactly. Restrict the source to what `go build`
      # actually reads, so only real code changes produce a new measurement.
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./go.mod
          ./go.sum
          ./cmd
          ./internal
          ./pkg
          ./api-spec
        ];
      };

      emulator = pkgs.buildGoModule {
        pname = "emulator";
        inherit version;
        inherit src;

        # The three sibling modules (api-spec, pkg/arkade, pkg/client) are wired by
        # local `replace` directives in the root go.mod, so a single src covers all four.
        #
        # Recompute whenever go.mod or go.sum changes. `version` does not affect it.
        #   1. Set the value below to `lib.fakeHash`.
        #   2. Run `nix build .#emulator`. It stops with a hash mismatch.
        #   3. Copy the `got:` value into the line below.
        #   4. Re-run `nix build .#emulator`. It now succeeds.
        # Always go through `lib.fakeHash`. A stale hash whose vendor directory is already
        # in /nix/store is reused without a rebuild, and go then fails much later with
        # "inconsistent vendoring".
        vendorHash = "sha256-sK4f/zVAH1Bj0T816cIHdIUbtdd5mbrGtlvgubbKJzA=";

        subPackages = [ "cmd" ];
        ldflags = [
          "-s"
          "-w"
          "-X"
          "main.Version=${version}"
        ];

        # cmd/emulator.go is `package main` under ./cmd, so the produced binary takes the
        # directory name. buildEif execs /app/<mainProgram>, so give it the real name.
        postInstall = ''
          mv "$out/bin/cmd" "$out/bin/emulator"
        '';

        # The test suite drives a regtest stack over the network.
        doCheck = false;

        meta.mainProgram = "emulator";
      };

      # ---------------------------------------------------------------------------------
      # Environments
      # ---------------------------------------------------------------------------------
      #
      # One measurement per environment is unavoidable. ENCLAVE_DEPLOYMENT selects the SSM
      # and KMS namespace and is in nonOverridableEnv, so two environments can never share
      # an EIF however much else they agree on. Everything that legitimately varies lives
      # here, in one reviewable place, rather than behind a boolean.
      #
      # Adding production is a new attribute here plus a `predecessor` below. Nothing in
      # mkEif needs to change.
      #
      #   prod = {
      #     deployment        = "ark/prod";
      #     region            = "eu-central-1";
      #     fqdn              = "emulator.arkade.sh";
      #     # No "letsencrypt" literal exists — tls.go:250 rejects anything that is not
      #     # "", "letsencrypt-staging", or an https:// URL. "" also works and selects
      #     # autocert's default, which is production; the URL is explicit.
      #     acmeDirectory     = "https://acme-v02.api.letsencrypt.org/directory";
      #     dev               = false;               # ten-year Object Lock, locked key
      #     # Omit to take the posture default of 24h.
      #     migrationCooldown = "336h";              # two weeks
      #   };
      environments = {
        dev = {
          deployment = "ark/dev";
          region = "eu-central-1";
          fqdn = "mutinynet.arkade.sh";
          acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory";
          dev = true;
          migrationCooldown = "0s";
        };

        se7enz = {
          deployment = "ark/se7enz";
          region = "eu-central-1";
          fqdn = "emulator.arklabs.se7enz.com";
          acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory";
          dev = true;
          migrationCooldown = "0s";
        };
      };

      # The measurement each environment succeeds. "genesis" only for a first deployment;
      # otherwise the live predecessor's PCR0, which the successor verifies before adopting
      # its state. Bump on every migration and record the generation.
      #
      #   dev:
      #     gen 1  genesis                                <- current
      #
      #   se7enz:
      #     gen 1  genesis                                <- current
      predecessors = {
        dev    = "genesis";
        se7enz = "genesis";
      };

      mkEif =
        env: predecessor:
        enclave.lib.buildEif {
          inherit pkgs;
          app = emulator;

          env = {
            # --- nonOverridableEnv ----------------------------------------------------
            # The SSM overlay refuses these by name. Changing any one is a new PCR0 and a
            # migration.

            # The SSM namespace prefix, joined as /<deployment>/<app>/..., so the slash is
            # intended: parameters land under /ark/se7enz/emulator/.
            ENCLAVE_DEPLOYMENT = env.deployment;
            ENCLAVE_APP_NAME = "emulator";

            # The predecessor this image may adopt state from, or "genesis".
            ENCLAVE_PREVIOUS_PCR0 = predecessor;

            # The emulator's signing key. The runtime generates a 32-byte secp256k1 key
            # via an attested KMS GenerateDataKey, keeps the ciphertext in SSM, and
            # injects it as 64 hex characters. The host cannot decrypt it: the instance
            # role has no kms:Decrypt. This is the property the whole design exists for.
            ENCLAVE_SECRETS_CONFIG = builtins.toJSON [
              {
                name = "emulator-secret-key";
                env_var = "EMULATOR_SECRET_KEY";
              }
            ];

            # ENCLAVE_DEV picks the whole security posture, and the two settings that make
            # a deployment disposable are reachable no other way: Object Lock retention
            # drops to 5 and 10 minutes from ten years, so the intent bucket can be emptied
            # and the deployment name reused, and the KMS key policy stays rewritable, so
            # losing the instance role does not strand the key.
            #
            # The cost is that the same root principal holds kms:PutKeyPolicy and can grant
            # itself Decrypt. Treat every secret in these environments as readable by
            # anyone holding account root. Attestation documents the enclave RECEIVES also
            # go unverified, so a host could forge a predecessor's lineage at migration.
            #
            # Not affected: the enclave still builds real hypervisor-signed attestations
            # through /dev/nsm, so clients verify it normally and KMS still enforces
            # kms:RecipientAttestation:PCR0 server-side.
            #
            # Production sets dev = false and takes the ten-year lock.
            ENCLAVE_DEV = lib.boolToString env.dev;

            # The posture default under ENCLAVE_DEV is 2s. "0s" removes the wait between
            # /request-migration and /finalise-migration entirely. Production drops this
            # line and takes the 24h.
            ENCLAVE_MIGRATION_COOLDOWN = env.migrationCooldown;

            # Asserts kvm-clock at boot. ENCLAVE_DEV would otherwise skip it, but the
            # paravirtualised clock is present on real Nitro, so override it back on.
            ENCLAVE_VERIFY_CLOCK_SOURCE = "true";
          }
          // {
            # --- Baked, though not in nonOverridableEnv -------------------------------
            # Not read after the overlay, so an SSM override arrives too late and does
            # nothing. ark-infra's app_env validation rejects them rather than let them
            # fail quietly.
            #
            # Related: https://github.com/ArkLabsHQ/enclave/issues/163

            # Necessarily before SSM — you need the region to reach SSM at all.
            ENCLAVE_AWS_REGION = env.region;

            # The emulator serves gRPC and grpc-gateway REST on one port. A TCP
            # passthrough NLB cannot split them, so the split happens here: "auto" matches
            # the upstream HTTP version to the inbound request. h2c would break HTTP/1.1
            # REST clients, h1 would break gRPC.
            ENCLAVE_UPSTREAM = "auto";

            # CloudWatch is the only telemetry backend and cannot be turned off. The
            # runtime creates /enclave/<deployment>/<app>/{logs,traces,metrics} on first
            # write and fails the boot if it cannot, so the instance role must carry the
            # logs grants before genesis. Only cadence and retention are settable.
            ENCLAVE_LOG_RETENTION_DAYS = "30";
            ENCLAVE_LOG_SHIP_INTERVAL = "5s";

            # --- Overridable from SSM -------------------------------------------------
            # Config.applyEnvOverride re-reads exactly these six after the overlay, so what
            # is baked here is a boot default. Override at /<deployment>/<app>/env/<NAME>
            # with no rebuild and no migration. All six are measured either way.

            ENCLAVE_APP_PORT = "7073";

            # Per-environment rather than SSM-only: a wrong default here means an enclave
            # requesting a certificate for the wrong name before anyone notices.
            ENCLAVE_FQDN = env.fqdn;

            # Inert as baked. LoadConfig never assigns the four ACME fields, so the SSM
            # overlay is the only thing that can enable ACME — without those parameters the
            # enclave serves a self-signed certificate whatever is written here. ark-infra
            # creates them.
            ENCLAVE_USE_ACME = "true";

            # Role address, not a personal one: it ships inside every copy of the image.
            ENCLAVE_ACME_EMAIL = "ops@arklabs.xyz";

            # Accepted values are "", "letsencrypt-staging", or an https:// URL.
            # "letsencrypt" is NOT valid and fails the boot with "unrecognized ACME
            # directory". Empty selects autocert's default, which is production.
            #
            # Production limits before iterating against it: 5 duplicate certificates per
            # week for the same hostname set, and 5 failed validations per hour. A genesis
            # needing several attempts can exhaust them.
            ENCLAVE_ACME_DIRECTORY = env.acmeDirectory;
          };
        };
    in
    {
      packages.${system} = {
        inherit emulator;

        # Nothing is called plain `eif`. The name carries the environment it is built for,
        # so an image cannot be mistaken for one built for somewhere else.
        #
        #   nix build .#eif-dev
        eif-dev    = mkEif environments.dev predecessors.dev;
        eif-se7enz = mkEif environments.se7enz predecessors.se7enz;

        default = emulator;
      };
    };
}
