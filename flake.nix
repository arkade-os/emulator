{
  description = "Arkade emulator, and its AWS Nitro Enclave image";

  inputs = {
    # Pinned to a revision carrying Go >= 1.26.6, which go.mod requires. nixpkgs-unstable
    # is still on 1.26.5 and the Nix sandbox cannot download a newer toolchain, so the
    # build would fail there.
    nixpkgs.url = "github:NixOS/nixpkgs/4651bb1e93b161a60975279b6ca8381de59d9a9c";

    # master, not a branch ref: the measurement must be reproducible from this file alone.
    # eddc621 is #151, horizontally scaled fleets. It removes tls-alpn-01 in favour of
    # DNS-01, so an ACME deployment now needs a Route53 hosted zone and Route53ZoneID in
    # SSM; replaces TLSCacheBucketName with CertBucketName and LeaseBucketName; and
    # derives the migration intent bucket name rather than reading it from SSM. None of
    # that changes the baked environment — nonOverridableEnv is unchanged and
    # nix/build-eif.nix is untouched — but ark-infra must provide it before first boot.
    enclave.url = "github:ArkLabsHQ/enclave/8e0eff6999c8191b1c3f6ff3dda575af8b67626a";
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
      #     intentRetention   = "87600h";            # see the note in mkEif before choosing
      #     migrationCooldown = "336h";              # two weeks
      #     shipLogs          = true;
      #   };
      environments = {
        dev = {
          deployment = "ark/dev";
          region = "eu-central-1";
          fqdn = "mutinynet.arkade.sh";
          acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory";
          intentRetention = "24h";
          migrationCooldown = "0s";
          shipLogs = true;
        };

        se7enz = {
          deployment = "ark/se7enz";
          region = "eu-central-1";
          fqdn = "emulator.arklabs.se7enz.com";
          acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory";
          intentRetention = "24h";
          migrationCooldown = "0s";
          shipLogs = true;
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
            # --- Fixed for the life of this measurement -------------------------------
            # These are runtime/environment.go's nonOverridableEnv. The SSM overlay
            # explicitly skips them, so changing any one is a new PCR0 and a migration.

            # Deployment is the SSM namespace prefix, joined as /<deployment>/<app>/...,
            # so a slash is intended: parameters land under /ark/se7enz/emulator/.
            ENCLAVE_DEPLOYMENT = env.deployment;
            ENCLAVE_APP_NAME = "emulator";
            ENCLAVE_PREVIOUS_PCR0 = predecessor;

            # Required, and has no default despite the README documenting one. Omitting
            # it produces an EIF that fails config validation and reboot-loops.
            #
            # This is a security parameter, not housekeeping: the runtime writes intents
            # under S3 Object Lock COMPLIANCE, so the window is how long an operator
            # cannot quietly wait out the anchor and roll back unnoticed. It is also
            # irreversible — nobody, including the account root, can shorten it, and the
            # bucket cannot be emptied until it expires. A previous genesis baked 87600h
            # and left a bucket that survives until 2036.
            #
            # Decide before genesis. The predecessor stamps it, and SSM cannot change it.
            ENCLAVE_MIGRATION_INTENT_RETENTION = env.intentRetention;

            # Explicit rather than implied. Unset also means 0, but leaving security
            # timing to a default is how the retention above got baked at ten years.
            ENCLAVE_MIGRATION_COOLDOWN = env.migrationCooldown;

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

            # ENCLAVE_KMS_KEY_LOCKED is deliberately UNSET, which means unlocked.
            #
            # Do not set it to true without reading this. The choice is permanent at
            # first lock, and a locked key gets no RootRecovery statement —
            # runtime/kms.go:134-137 only adds one when the key is unlocked. Without it,
            # kms:ScheduleKeyDeletion is granted solely to the enclave instance role, so
            # once that role is destroyed the key can never be deleted by anyone,
            # including the account root. Unlocked also selects the /unlocked/ SSM
            # segment for every KMS-subtree path.
            #
            # ENCLAVE_DEV is unset, and there is deliberately no switch for setting it.
            # It makes the runtime accept attestation documents the Nitro hypervisor never
            # signed (runtime.go:175) and poll the clock every 5s (clocksync_linux.go:66).
            # It belongs to a local harness running against mocked AWS, which this repo
            # does not have. Do not add the switch back without the harness that uses it.
            #
            # ENCLAVE_VERIFY_CLOCK_SOURCE is likewise unset. Enabling it asserts
            # kvm-clock at boot; worth doing on real Nitro, but not worth introducing a
            # new way for a genesis to fail to boot. Revisit once a chain is live.
            ENCLAVE_VERIFY_CLOCK_SOURCE = "true";
          }
          // {
            # --- Baked, despite not being in nonOverridableEnv -------------------------
            # A variable is only genuinely overridable if it is also read AFTER
            # ApplyEnvOverrides, which runs at runtime.go:153. Everything in this block
            # is read before that, so an SSM override arrives too late and silently does
            # nothing. Upstream: ArkLabsHQ/enclave#163.

            # runtime.go:48, building the AWS clients. Necessarily before SSM — you need
            # the region to reach SSM at all.
            ENCLAVE_AWS_REGION = env.region;

            # config.go:48 and config.go:60, at process entry.
            #
            # APP_PORT is worse than a no-op if overridden: config.go:48 fixes the proxy
            # target while runtime.go:189 passes the overridden value to the child, so
            # the app moves and the proxy does not.
            #
            # The emulator serves gRPC and grpc-gateway REST on one port. A TCP
            # passthrough NLB cannot split them, so the split happens here: `auto`
            # matches the upstream HTTP version to the inbound request. h2c would break
            # HTTP/1.1 REST clients, h1 would break gRPC.
            ENCLAVE_APP_PORT = "7073";
            ENCLAVE_NITRIDING_UPSTREAM = "auto";

            # runtime.go:69. NewLogging calls cloudwatchLogsEnabled() — a plain
            # os.Getenv — and nils the ship channel when false, so by line 153 the
            # shipper is already disabled. Verified: setting this in SSM and restarting
            # created no log groups. Tracing has the same shape at runtime.go:54.
            #
            # Groups are named /enclave/<deployment>/<app>/{logs,traces} by the runtime,
            # which does not match the /ark/<env>/<component>/<name> house convention.
            # The prefix is a literal in logging.go:178 and tracing.go:65.
            ENCLAVE_LOG_CLOUDWATCH = lib.boolToString env.shipLogs;
            ENCLAVE_LOG_RETENTION_DAYS = "30";
            ENCLAVE_LOG_SHIP_INTERVAL = "5s";

            # --- Genuinely overridable from SSM ---------------------------------------
            # tls.go:80 re-reads exactly these five by name after the overlay, so they
            # are boot defaults rather than fixed values. Override at
            # /<deployment>/<app>/env/<NAME> with no rebuild and no migration.
            #
            # FQDN is the one of the five that LoadConfig also reads, at config.go:55,
            # so it works from the environment today. The four ACME settings do not:
            # LoadConfig never assigns them, so what is written here is inert until
            # ArkLabsHQ/enclave#166 lands, and SSM is the only thing configuring ACME.
            # All five are measured into PCR0 either way.
            #
            # The FQDN is still per-environment rather than SSM-only, because a wrong
            # default here means an enclave requesting a certificate for the wrong name
            # before anyone notices, and because two environments already differ in
            # measurement — there is nothing to gain by leaving it blank.
            #
            # CONSEQUENCE FOR A FRESH GENESIS: with the SSM tree empty, cfg.UseACME holds
            # its zero value, so tls.go:66 serves a self-signed certificate regardless of
            # what is baked here. Create the ENCLAVE_NITRIDING_USE_ACME and
            # _ACME_DIRECTORY parameters under /<deployment>/<app>/env/ before expecting a
            # real certificate.
            ENCLAVE_NITRIDING_FQDN = env.fqdn;
            ENCLAVE_NITRIDING_USE_ACME = "true";

            # Role address, not a personal one: whatever is set here ships inside every
            # copy of the image and is covered by the measurement.
            ENCLAVE_NITRIDING_ACME_EMAIL = "ops@arklabs.xyz";

            # Production Let's Encrypt. Note the limits before iterating against it: 5
            # duplicate certificates per week for the same hostname set, and 5 failed
            # validations per hour. A genesis needing several attempts can exhaust them
            # and leave a live deployment unable to reissue.
            #
            # Accepted values are "", "letsencrypt-staging", or an https:// URL
            # (tls.go:243-251). "letsencrypt" is NOT valid and fails at boot with
            # "unrecognized ACME directory". Empty selects autocert's default, which is
            # production Let's Encrypt.
            #
            # Switching to production is an SSM override, not a rebuild — and today it is
            # ONLY an SSM override, because LoadConfig never reads this.
            ENCLAVE_NITRIDING_ACME_DIRECTORY = env.acmeDirectory;
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
