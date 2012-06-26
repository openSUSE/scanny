require_relative "system_check"

module Scanny
  module Checks
    module SystemTools
      class UnzipCheck < SystemCheck
        def pattern
          [
            check_usage_for('unzip\s+[^(=|&)]'),
            check_usage_for('unzip.*-:')
          ].join("|")
        end

        def check(node)
          if Machete.matches?(node, check_usage_for('unzip.*-:'))
            issue :high, warning_message, :cwe => [23, 88]
          elsif Machete.matches?(node, check_usage_for('unzip\s+[^(=|&)]'))
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