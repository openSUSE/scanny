module Scanny
  module Checks
    # Checks for indication that a low-entropy random number generator is used.
    class RandomNumbersCheck < Check
      def pattern
        <<-EOT
          Send<receiver = Self | ConstantAccess<name = :Kernel>, name = :rand | :srand>
          |
          SendWithArguments<receiver = Self | ConstantAccess<name = :Kernel>, name = :rand | :srand>
        EOT
      end

      def check(node)
        issue :medium, "The \"#{node.name}\" method indicates using low-entropy random number generator.",
              :cwe => 331
      end
    end
  end
end
