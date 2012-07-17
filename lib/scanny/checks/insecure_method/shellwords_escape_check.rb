module Scanny
  module Checks
    module InsecureMethod
      class ShellwordsEscapeCheck < Check
        def pattern
          [
            pattern_shellwords_escape,
            pattern_shell_escape
          ].join("|")
        end

        def check(node)
          issue :high, warning_message, :cwe => 184
        end

        private

        def warning_message
          "Execute escape method from Shellwords module" +
          "can lead incomplete input filtering"
        end

        # Shellwords.escape("string")
        def pattern_shellwords_escape
          <<-EOT
            SendWithArguments<
              receiver = ConstantAccess<name = :Shellwords>,
              name = :escape
            >
          EOT
        end

        # shell_escape("string")
        def pattern_shell_escape
          "SendWithArguments<name = :shell_escape>"
        end
      end
    end
  end
end