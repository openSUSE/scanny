module Scanny
  module Checks
    module SystemTools
      class SudoCheck < Check
        include ::Scanny::Checks::Helpers

        def pattern
          build_pattern_exec_command('sudo')
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