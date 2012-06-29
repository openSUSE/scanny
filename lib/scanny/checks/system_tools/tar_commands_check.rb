module Scanny
  module Checks
    module SystemTools
      class TarCommandsCheck < Check
        include Scanny::Checks::Helpers

        def pattern
          [
            build_pattern_exec_command(/tar.*\-\-to\-command/),
            build_pattern_exec_command(/tar.*\-\-rmt\-command/),
            build_pattern_exec_command(/tar.*\-\-rsh\-command/)
          ].join("|")
        end

        def check(node)
          issue :high, warning_message, :cwe => 88
        end

        private

        def warning_message
          "Tar command has an option that allows to run external programs"
        end
      end
    end
  end
end