unless defined?(RUBY_ENGINE) && RUBY_ENGINE == "rbx" && RUBY_VERSION >= '1.9'
  desc = defined?(RUBY_DESCRIPTION) ? RUBY_DESCRIPTION : "ruby #{RUBY_VERSION} (#{RUBY_RELEASE_DATE})"
  abort <<-end_message

      Scanny requires Rubinius in 1.9 mode.

      You're running
        #{desc}

      Please change your Ruby implementation to continue.

  end_message

  raise abort
end
