# Code taken from http://blog.wolfman.com/articles/2008/1/2/xpath-matchers-for-rspec

require 'rexml/document'
require 'rexml/element'

RSpec::Matchers.define :have_xml do |xpath, text|
  match do |body|
    doc = REXML::Document.new body
    nodes = REXML::XPath.match(doc, xpath)
    nodes.empty?.should be_false
    if text
      nodes.each do |node|
        node.text.should == text
      end
    end
    true
  end

  failure_message_for_should do |body|
    "expected to find xml tag #{xpath} in:\n#{body}"
  end

  failure_message_for_should_not do |response|
    "expected not to find xml tag #{xpath} in:\n#{body}"
  end

  description do
    "have xml tag #{xpath}"
  end
end
