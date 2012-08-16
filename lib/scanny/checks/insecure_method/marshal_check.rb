module Scanny
  module Checks
    module InsecureMethod
      class MarshalCheck < Check
        def pattern
          pattern_load_call
        end

        def check(node)
          issue :high, warning_message, :cwe => 502
        end

        private

        def warning_message
          "Execute deserialize method can load to memory dangerous object"
        end

        # Marshal.load(object)
        def pattern_load_call
          <<-EOT
            SendWithArguments<
              name = :load | :restore,
              receiver = ConstantAccess<
                name = :Marshal
              >
            >
          EOT
        end
      end
    end
  end
end