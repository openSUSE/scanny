module Scanny
  module Checks
    class TestCheck < Check
      def pattern
        'FixnumLiteral'
      end

      def check(node)
        issue :high, "Hey, I found unsecure code!", :cwe => 42
        issue :high, "Hey, I found more unsecure code!", :cwe => 43
        issue :low,  "OK, this is unsecure too, but not that much"
      end
    end
  end
end