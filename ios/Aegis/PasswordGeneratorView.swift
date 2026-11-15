import SwiftUI

@MainActor
struct PasswordGeneratorView: View {
    @Environment(\.dismiss) private var dismiss
    let onUse: (String) -> Void

    @AppStorage("generator.passphrase") private var passphraseMode = false
    @AppStorage("generator.length") private var length: Double = 24
    @AppStorage("generator.uppercase") private var uppercase = true
    @AppStorage("generator.lowercase") private var lowercase = true
    @AppStorage("generator.numbers") private var numbers = true
    @AppStorage("generator.special") private var special = true
    @AppStorage("generator.ambiguous") private var ambiguous = true
    @AppStorage("generator.words") private var wordCount: Double = 6
    @AppStorage("generator.separator") private var separator = "-"

    @State private var generated = ""
    @State private var copied = false

    /// Changes whenever an option changes; drives regeneration.
    private var optionsKey: String {
        [
            passphraseMode ? "p" : "c",
            String(Int(length)),
            uppercase ? "U" : "u",
            lowercase ? "L" : "l",
            numbers ? "N" : "n",
            special ? "S" : "s",
            ambiguous ? "A" : "a",
            String(Int(wordCount)),
            separator,
        ].joined(separator: "|")
    }

    private var noCharacterSet: Bool {
        !uppercase && !lowercase && !numbers && !special
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(generated.isEmpty ? "Select at least one character set" : generated)
                        .font(.title3.monospaced())
                        .foregroundStyle(generated.isEmpty ? Color.secondary : Color.primary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 6)
                    HStack {
                        Button {
                            regenerate()
                        } label: {
                            Label("Regenerate", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(.borderless)
                        Spacer()
                        Button {
                            Clipboard.copy(generated)
                            copied = true
                        } label: {
                            Label(copied ? "Copied" : "Copy", systemImage: "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .disabled(generated.isEmpty)
                    }
                }

                Section {
                    Picker("Mode", selection: $passphraseMode) {
                        Text("Password").tag(false)
                        Text("Passphrase").tag(true)
                    }
                    .pickerStyle(.segmented)
                }

                if passphraseMode {
                    Section("Passphrase") {
                        VStack(alignment: .leading) {
                            Text("Words: \(Int(wordCount))")
                            Slider(value: $wordCount, in: 4...10, step: 1)
                        }
                        Picker("Separator", selection: $separator) {
                            Text("Hyphen ( - )").tag("-")
                            Text("Space").tag(" ")
                            Text("Period ( . )").tag(".")
                            Text("Underscore ( _ )").tag("_")
                        }
                    }
                } else {
                    Section("Password") {
                        VStack(alignment: .leading) {
                            Text("Length: \(Int(length))")
                            Slider(value: $length, in: 15...64, step: 1)
                        }
                        Toggle("Uppercase (A-Z)", isOn: $uppercase)
                        Toggle("Lowercase (a-z)", isOn: $lowercase)
                        Toggle("Numbers (0-9)", isOn: $numbers)
                        Toggle("Symbols (!@#…)", isOn: $special)
                        Toggle("Include look-alike characters (0 O I l 1…)", isOn: $ambiguous)
                    }
                }
            }
            .navigationTitle("Generator")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Use") {
                        onUse(generated)
                        dismiss()
                    }
                    .disabled(generated.isEmpty)
                }
            }
            .task(id: optionsKey) {
                await regenerate()
            }
        }
    }

    private func regenerate() {
        copied = false
        if passphraseMode {
            generated = AegisCore.passphrase(wordCount: Int(wordCount), separator: separator)
        } else if noCharacterSet {
            generated = ""
        } else {
            generated = AegisCore.password(
                length: Int(length),
                uppercase: uppercase,
                lowercase: lowercase,
                numbers: numbers,
                special: special,
                ambiguous: ambiguous
            )
        }
    }
}
