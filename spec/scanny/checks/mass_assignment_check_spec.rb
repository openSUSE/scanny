require "spec_helper"

module Scanny::Checks
  describe MassAssignmentCheck do
    before do
      @runner = Scanny::Runner.new(MassAssignmentCheck.new)
      @message =  "Create objects without defense against mass assignment" +
                  "can cause dangerous errors in the database"
      @issue = issue(:high, @message, 642)
    end

    it "reports \"User.new(params[:user])\" correctly" do
      @runner.should check("User.new(params[:user])").with_issue(@issue)
    end

    it "reports \"User.new(:email => params[:input])\" correctly" do
      @runner.should check("User.new(:email => params[:input])").with_issue(@issue)
      @runner.should check("User.new(params[:input] => :value)").without_issues
    end

    it "reports \"User.create(params[:user])\" correctly" do
      @runner.should check("User.create(params[:user])").with_issue(@issue)
    end

    it "reports \"@user.update_attributes(params[:user])\" correctly" do
      @runner.should check("@user.update_attributes(params[:user])").with_issue(@issue)
    end

  end
end
