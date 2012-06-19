require "spec_helper"

module Scanny::Checks::Sql
  describe StringInterpolationWithParamsCheck do
    before do
      @runner = Scanny::Runner.new(StringInterpolationWithParamsCheck.new)
      @message =  "Use of external parameters in queries to the database " +
                  "can lead to SQL injection issue"
      @issue_high = issue(:high, @message, 89)
    end

    it "reports string interpolation with \"options[:select]\" correctly" do
      @runner.should check('"SELECT #{options[:select]}"').with_issue(@issue_high)
    end

    it "reports string interpolation with \"options[:select]\" correctly" do
      @runner.should check('"SELECT #{params[:input]}"').with_issue(@issue_high)
    end
  end
end


