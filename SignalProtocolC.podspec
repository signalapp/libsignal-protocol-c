Pod::Spec.new do |s|
  s.name         = "SignalProtocolC"
  s.version      = "0.1.0"
  s.summary      = "Signal Protocol C Library"

  s.description  = <<-DESC
                  This is a ratcheting forward secrecy protocol that works in synchronous and asynchronous messaging environments.
                   DESC

  s.homepage     = "https://github.com/WhisperSystems/libsignal-protocol-c"

	s.license = { :type => 'GPLv3', :text => <<-LICENSE
                Copyright 2015-2016 Open Whisper Systems

								Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

								Additional Permissions For Submission to Apple App Store: Provided that you are otherwise in compliance with the GPLv3 for each covered work you convey (including without limitation making the Corresponding Source available in compliance with Section 6 of the GPLv3), Open Whisper Systems also grants you the additional permission to convey through the Apple App Store non-source executable versions of the Program as incorporated into each applicable covered work as Executable Versions only under the Mozilla Public License version 2.0 (https://www.mozilla.org/en-US/MPL/2.0/).

                LICENSE
               }
  s.author             = { "Open Whisper Systems" => "support@whispersystems.org" }
  s.social_media_url   = "https://twitter.com/whispersystems/"

  s.source       = { :git => "https://github.com/WhisperSystems/libsignal-protocol-c.git", 
  					 				 :commit => 'b0f0e72159849bd1505d2af510bdd51d8871ce73'}

  s.source_files  = ["src/**/*.{h,c}"]
  s.exclude_files = 'src/curve25519/ed25519/main'
  s.public_header_files = ["src/signal_protocol.h", "src/signal_protocol_types.h", "src/curve.h", "src/hkdf.h", "src/ratchet.h", "src/protocol.h", "src/session_state.h", "src/session_record.h", "src/session_pre_key.h", "src/session_builder.h", "src/session_cipher.h", "src/key_helper.h", "src/sender_key.h", "src/sender_key_state.h", "src/sender_key_record.h", "src/group_session_builder.h", "src/group_cipher.h", "src/fingerprint.h"]

  s.xcconfig = { 'HEADER_SEARCH_PATHS' => '$(PODS_ROOT)/SignalProtocolC/src $(PODS_ROOT)/SignalProtocolC/src/curve25519 $(PODS_ROOT)/SignalProtocolC/src/curve25519/ed25519 $(PODS_ROOT)/SignalProtocolC/src/protobuf-c' }
end
