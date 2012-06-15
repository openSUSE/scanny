require "spec_helper"

module Scanny::Checks
  describe XssRenderApiCheck do
    before :each do
      @runner = Scanny::Runner.new(XssRenderApiCheck.new)
      @warning_message = "Assigning request parameters into render_api_error can lead to XSS issues."
      @issue_high   = Scanny::Issue.new("scanned_file.rb", 1, :high, @warning_message, 79)
      @issue_medium = Scanny::Issue.new("scanned_file.rb", 1, :medium, @warning_message, 79)
    end

    it "reports \"render_api_error(params[:password])\" correctly" do
      @runner.should check("render_api_error(params[:password])").with_issue(@issue_high)
    end

    it "reports \"render_api_error(\"\#{interpolation}\")\" correctly" do
      @runner.should check('render_api_error("#{interpolation}")').with_issue(@issue_medium)
    end
  end
end
