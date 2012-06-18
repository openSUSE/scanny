require "spec_helper"

module Scanny::Checks::Sql
  describe SanitizeCheck do
    before do
      @runner = Scanny::Runner.new(SanitizeCheck.new)
      @message =  "Use of external parameters in queries to the database " +
                  "can lead to SQL injection issue"
      @issue_info = issue(:info, @message, 89)
    end

    it "reports \"sanitize_sql\" calls correctly" do
      @runner.should check("'mysql_query'.sanitize_sql").with_issue(@issue_info)
    end
  end
end
