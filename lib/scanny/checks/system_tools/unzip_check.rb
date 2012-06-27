module Scanny
  module Checks
    module SystemTools
      class UnzipCheck < Check
        include ::Scanny::Checks::Helpers

        def pattern
          [
            build_pattern_exec_command('unzip\s+[^(=|&)]'),
            build_pattern_exec_command('unzip.*-:')
          ].join("|")
        end

        def check(node)
          if Machete.matches?(node, build_pattern_exec_command('unzip.*-:'))
            issue :high, warning_message, :cwe => [23, 88]
          elsif Machete.matches?(node, build_pattern_exec_command('unzip\s+[^(=|&)]'))
            issue :medium, warning_message, :cwe => [23, 88]
          end
        end

        private

        def warning_message
          "Unzip option allows '../' in archived file path, dir traversal"
        end
      end
    end
  end
end