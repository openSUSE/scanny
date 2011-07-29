require "spec_helper"

module Scanny
  describe Runner do
    describe "given a custom config file" do
      before do
        @runner = Runner.new
      end

      it "uses check from it" do
        # @runner.check_file(File.expand_path(File.dirname(__FILE__) + '/../fixtures/test_class.rb'))
        input = <<-RUBY
          class TestClass

            def METHOD

            end
          end
        RUBY
        @runner.check("scanned_file.rb", input).should be_empty
      end
    end
  end
end
