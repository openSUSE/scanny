module Scanny
  module Checks
    module SystemTools
      class TarCheck < Check
        include Scanny::Checks::Helpers

        def pattern
          build_pattern_exec_command(/tar\s+/)
        end

        def check(node)
          issue :medium, warning_message, :cwe => 88
        end

        private

        def warning_message
          "Tar command can execute dangerous operations on files" +
          "and can travel through directories"
        end
      end
    end
  end
end