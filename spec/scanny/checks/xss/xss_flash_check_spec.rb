require "spec_helper"

module Scanny::Checks
  describe XssFlashCheck do
    before :each do
      @runner = Scanny::Runner.new(XssFlashCheck.new)
      @warning_message = "Assigning request parameters into flash can lead to XSS issues."
      @issue_high = Scanny::Issue.new("scanned_file.rb", 1, :high, @warning_message, 79)
      @issue_medium = Scanny::Issue.new("scanned_file.rb", 1, :medium, @warning_message, 79)
    end

    it "reports \"flash[:warning] = params[:password]\" correctly" do
      @runner.should check("flash[:warning] = params[:password]").with_issue(@issue_high)
    end

    it "reports \"flash[:warning] = \"\#{interpolation}\" correctly" do
      @runner.should check('flash[:warning] = "#{value}"').with_issue(@issue_medium)
      @runner.should check("flash[:warning] = \"Static warning\"").without_issues
    end
  end
end
