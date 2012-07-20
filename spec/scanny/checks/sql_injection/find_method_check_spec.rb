require "spec_helper"

module Scanny::Checks::Sql
  describe FindMethodCheck do
    before do
      @runner = Scanny::Runner.new(FindMethodCheck.new)
      @message = "Use of external parameters in queries to the database " +
                 "can lead to SQL injection issue"
      @issue_low = issue(:low, @message, 89)
    end

    it "reports \"find\" calls with :conditions key and static value correctly" do
      @runner.should  check("find(:first, :conditions => { :id => 10 })").
                      with_issue(@issue_low)
    end

    it "does not report \"find\" calls without first argument" do
      @runner.should  check("find(:conditions => { :id => 10 })").
                      without_issues
    end

    it "does not report \"find\" with wrong key" do
      @runner.should  check("find(:first, :hello => :conditions)").
                      without_issues
    end

    it "reports \"find\" calls with :conditions key and dynamic value correctly" do
      @runner.should  check('find(:first, :conditions => "#{method}")').
                      with_issue(@issue_low)
    end

    it "reports \"find\" calls with :conditions key and params method as value correctly" do
      @runner.should  check("find(:first, :conditions => params[:id])").
                      with_issue(@issue_low)
    end

    it "reports \"execute\" calls on class correctly" do
      @runner.should check('User.execute').with_issue(@issue_low)
    end

    it "reports \"find_by_sql\" calls on class correctly" do
      @runner.should check('User.find_by_sql').with_issue(@issue_low)
    end

    it "reports \"paginate\" calls on class correctly" do
      @runner.should check('User.paginate').with_issue(@issue_low)
    end

    it "reports \"find_by_sql\" calls on class with params correctly" do
      @runner.should  check('User.find_by_sql params[:password]').
                      with_issue(@issue_low)
    end
  end
end
