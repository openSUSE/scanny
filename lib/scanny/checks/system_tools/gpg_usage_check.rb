module Scanny
  module Checks
    module SystemTools
      class GpgUsageCheck < Check
        include Scanny::Checks::Helpers

        def pattern
          [
            pattern_gpg_class,
            pattern_gpg_method,
            build_pattern_exec_command('gpg')
          ].join("|")
        end

        def check(node)
          issue :info, warning_message, :cwe => 0
        end

        private

        def warning_message
          "Using gpg tool in the wrong way can lead to security problems"
        end

        # GPG.method
        def pattern_gpg_class
          <<-EOT
          Send | SendWithArguments
          <
            receiver = ConstantAccess<
              name =
                :GPG |
                :Gpg |
                :GpgKey
            >
          >

          EOT
        end

        # gpg()
        def pattern_gpg_method
          "Send | SendWithArguments<name = :gpg>"
        end
      end
    end
  end
end