module Scanny
  module Checks
    class ExtendCheck < Check; end

    class MyCheck < ExtendCheck
      def pattern
        'NilClass'
      end
    end
  end
end
