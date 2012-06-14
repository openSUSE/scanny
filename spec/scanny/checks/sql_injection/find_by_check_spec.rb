require "spec_helper"

module Scanny::Checks
  describe FindByCheck do
    before do
      @runner = Scanny::Runner.new(FindByCheck.new)
      @message = "Use of external parameters in queries to the database " +
                 "can lead to SQL injection issue"
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
  end
end
