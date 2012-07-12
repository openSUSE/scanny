module Scanny
  module Checks
    class ExtendCheck < Check; end

    class MyCheck < ExtendCheck
      def pattern
        ''
      end
    end
  end
end