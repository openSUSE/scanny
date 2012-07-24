require "spec_helper"

module Scanny::Checks::Sql
  describe FindMethodWithDynamicStringCheck do
    before do
      @runner = Scanny::Runner.new(FindMethodWithDynamicStringCheck.new)
      @message =  "Use of external parameters in queries to the database " +
                  "can lead to SQL injection issue"
      @issue_medium = issue(:medium, @message, 89)
    end

    it "reports \"find\" calls with :conditions key and dynamic value correctly" do
      @runner.should  check('find(:first, :conditions => "#{method}")').
                      with_issue(@issue_medium)
      @runner.should check('find(:first, :conditions => "normal_string")').without_issues
    end

    it "does not report \"find\" calls without first argument" do
      @runner.should check("find(:conditions => :value)").without_issues
    end

    it "does not report \"find\" calls with incorrect hash value" do
      @runner.should  check('find(:first, "#{conditions}" => :value)').
                      without_issues
    end
  end
end
