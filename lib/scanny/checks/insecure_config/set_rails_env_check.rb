module Scanny
  module Checks
    # Checks for places where ENV["RAILS_ENV"] is set.
    class SetRailsEnvCheck < Check
      # ENV["RAILS_ENV"] = "test"
      def pattern
        <<-EOT
          ElementAssignment<
            receiver  = ConstantAccess<name = :ENV>,
            arguments = ActualArguments<
              array = [StringLiteral<string = "RAILS_ENV">, any]
            >
          >
        EOT
      end

      def check(node)
        issue :info,
          "Setting ENV[\"RAILS_ENV\"] can indicate insecure configuration.",
          :cwe => 209
      end
    end
  end
end
