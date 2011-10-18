module Scanny
  module Checks
    # Checks for use of "File.open" without block, potential FD leak. Using blocks ensures
    # auto close.
    class FDLeakCheck < Check
      def pattern
        <<-EOT
          SendWithArguments<
            name  = :open,
            block = nil,
            receiver = ConstantAccess<name = :File>
          >
        EOT
      end

      def check(node)
        issue :info,
          "Using File.open without block might lead to file descriptor leak, unless file is explicitly closed."
      end
    end
  end
end
