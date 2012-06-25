require_relative "system_check"

module Scanny
  module Checks
    module SystemTools
      class GpgUsageCheck < SystemCheck
        def pattern
          [
            pattern_gpg_class,
            pattern_gpg_method,
            check_usage_for(:gpg)
          ].join("|")
        end

        def check(node)
          issue :info, warning_message, :cwe => 0
        end

        private

        def warning_message
          "Using gpg tool in the wrong way can lead to security problems"
        end

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

        def pattern_gpg_method
          "Send | SendWithArguments<name = :gpg>"
        end
      end
    end
  end
end