module Scanny
  module Checks
    class TestStrictCheck < Check
      def pattern
        'FixnumLiteral'
      end

      def check(node)
        puts 'strict checked'
      end

      def strict?
        true
      end
    end
  end
end