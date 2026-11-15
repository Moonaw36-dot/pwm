import AuthenticationServices
import SwiftUI
import UIKit

/// Entry point iOS loads when the user picks Aegis from the password bar or
/// the AutoFill sheet. Nothing is registered with the system's credential
/// store, so iOS never sees labels or usernames: every fill goes through this
/// unlock-and-pick screen.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let model = AutoFillModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        model.onCancel = { [weak self] in
            self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
        }
        model.onPick = { [weak self] user, password in
            let credential = ASPasswordCredential(user: user, password: password)
            self?.extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
        }

        let host = UIHostingController(rootView: AutoFillView(model: model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.setServices(serviceIdentifiers.map { (identifier: $0.identifier, isURL: $0.type == .URL) })
    }
}
