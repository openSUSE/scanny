require "spec_helper"

module Scanny::Checks::Sql
  describe FindByCheck do
    before do
      @runner = Scanny::Runner.new(FindByCheck.new)
      @message = "Use of external parameters in queries to the database " +
                 "can lead to SQL injection issue"
      @issue_info = issue(:info, @message, 89)
      @issue_low = issue(:low, @message, 89)
      @issue_medium = issue(:medium, @message, 89)
      @issue_high = issue(:high, @message, 89)
    end

    it "reports \"find_by_\" calls with \"params[:description]\" correctly" do
      @runner.should check("find_by_description(params[:description])").with_issue(@issue_low)
      @runner.should check("find_by_description(no_params[:description])").without_issues
    end

    it "reports \"find\" calls with :conditions key and static value correctly" do
      @runner.should check("find(:first, :conditions => { :id => 10 })").with_issue(@issue_low)
    end

    it "reports \"find\" calls with :conditions key and dynamic value correctly" do
      @runner.should check('find(:first, :conditions => "#{method}")').with_issue(@issue_medium)
    end

    it "reports \"find\" calls with :conditions key and params method as value correctly" do
      @runner.should check("find(:first, :conditions => params[:id])").with_issue(@issue_high)
      @runner.should_not check("find(:first, :conditions => no_params[:id])").with_issue(@issue_high)
    end

    it "reports \"find\" calls with :limit key and params method as value correctly" do
      @runner.should check("find(:first, :limit => params[:id])").with_issue(@issue_high)
      @runner.should_not check("find(:first, :limit => no_params[:id])").with_issue(@issue_high)
    end

    it "reports \"find\" calls with :conditions key and session method as value correctly" do
      @runner.should check("find(:first, :conditions => session[:password])").with_issue(@issue_high)
      @runner.should_not check("find(:first, :conditions => no_session[:password])").with_issue(@issue_high)
    end

    it "reports \"find\" calls with :limit key and session method as value correctly" do
      @runner.should check("find(:first, :limit => session[:password])").with_issue(@issue_high)
      @runner.should_not check("find(:first, :limit => no_session[:password])").with_issue(@issue_high)
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

    it "reports \"execute\" calls on class with params correctly" do
      @runner.should check('User.execute params[:password]').with_issue(@issue_high)
    end

    it "reports \"find_by_sql\" calls on class with params correctly" do
      @runner.should check('User.find_by_sql params[:password]').with_issue(@issue_high)
    end

    it "reports \"paginate\" calls on class with params correctly" do
      @runner.should check('User.paginate params[:password]').with_issue(@issue_high)
    end
  end
end
