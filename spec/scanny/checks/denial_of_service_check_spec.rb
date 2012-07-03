require "spec_helper"

module Scanny::Checks
  describe DenialOfServiceCheck do
    before do
      @runner = Scanny::Runner.new(DenialOfServiceCheck.new)
      @message =  "Using \"LIKE\" in queries may lead to " +
                  "the unavailability of the application"
      @issue = issue(:medium, @message, 400)
    end

    it "reports \"User.find(:first, :conditions => \"name LIKE '%bob%'\" )\" correctly" do
      @runner.should  check("User.find(:first, :conditions => \"name LIKE '%bob%'\" )").
                      with_issue(@issue)
    end

    it "reports \"User.find(:first, :limit => \"name LIKE '%bob%'\" )\" correctly" do
      @runner.should  check("User.find(:first, :limit => \"name LIKE '%bob%'\" )").
                          with_issue(@issue)
    end
  end
end
