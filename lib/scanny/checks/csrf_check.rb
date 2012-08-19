module Scanny
  module Checks
    # Checks for use of the "protect_from_forgery" method.
    class CSRFCheck < Check
      # protect_from_forgery
      def pattern
        "Send<receiver = Self, name = :protect_from_forgery>"
      end

      def check(node)
        issue :info, "The \"protect_from_forgery\" method is used.", :cwe => 352
      end

      def strict?
        true
      end
    end
  end
end
