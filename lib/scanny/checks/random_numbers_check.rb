module Scanny
  module Checks
    # Checks for indication that a low-entropy random number generator is used.
    class RandomNumbersCheck < Check
      def pattern
        [
          pattern_rand,
          pattern_seed,
          pattern_urandom
        ].join("|")
      end

      def check(node)
        issue :medium, warning_message, :cwe => 331
      end

      private

      def warning_message
        "This action indicates using low-entropy random number generator"
      end

      def pattern_rand
        <<-EOT
          Send<
            receiver = Self | ConstantAccess<name = :Kernel>,
            name = :rand | :srand
          >
          |
          SendWithArguments<
            receiver = Self | ConstantAccess<name = :Kernel>,
            name = :rand | :srand
          >
        EOT
      end

      def pattern_seed
        <<-EOT
          Send<name = :seed>
          |
          SendWithArguments<name = :seed>
        EOT
      end

      def pattern_urandom
        "StringLiteral<string *= /urandom/>"
      end
    end
  end
end
