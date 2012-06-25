module Scanny
  module Checks
    module SystemTools
      class SudoCheck < SystemCheck
        def pattern
          check_usage_for(:sudo)
        end

        def check(node)
          issue :info, warning_message, :cwe => 0
        end

        private

        def warning_message
          "Using sudo can lead to the execution" +
          "of programs on root administrator rights"
        end
      end
    end
  end
end