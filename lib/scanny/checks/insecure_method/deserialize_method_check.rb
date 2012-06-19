module Scanny
  module Checks
    module InsecureMethod
      class DeserializeMethodCheck < Check
        def pattern
          pattern_deserialize_call
        end

        def check(node)
          issue :high, warning_message, :cwe => 502
        end

        private

        def warning_message
          "Execute deserialize method can load to memory dangerous object"
        end

        def pattern_deserialize_call
          <<-EOT
            SendWithArguments | Send
              <name = :deserialize>
          EOT
        end
      end
    end
  end
end