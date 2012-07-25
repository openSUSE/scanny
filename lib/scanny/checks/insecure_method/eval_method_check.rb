module Scanny
  module Checks
    module InsecureMethod
      class EvalMethodCheck < Check
        def pattern
          pattern_eval_call
        end

        def check(node)
          issue :high, warning_message, :cwe => 95
        end

        private

        def warning_message
          "Execute eval method can lead the ruby interpreter to run dangerous code"
        end

        # eval("ruby_code")
        def pattern_eval_call
          <<-EOT
            SendWithArguments<name = :eval>
            |
            Send<name = :eval>
          EOT
        end
      end
    end
  end
end