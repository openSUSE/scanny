module Scanny
  module Checks
    module Sql
      class SqlCheck < Check
        private

        def warning_message
          "Use of external parameters in queries to the database " +
          "can lead to SQL injection issue"
        end
      end
    end
  end
end