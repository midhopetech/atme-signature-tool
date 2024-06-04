# ATME-signature-tool

## Installation
<ol>
    <li>Download the <strong>“ATME-signature-tool.zip”</strong>> archive (Code > Download ZIP)</li>
    <li>Unzip the <strong>“ATME-signature-tool”</strong></li>
</ol>

## Message Signing
<ol>
    <li>Run the “index.html” page using your Internet browser</li>
    <li>Fill out the secret phrase received from the Validator in the <strong>Message</strong> field.</li>
    <li>
        Fill the private key in the Private key field.
        <ol>
            <li>Option 1: Copy and paste the private key in the Private key field.</li>
            <li>Option 2: Download the private key in the Private key field using the Upload button and specifying the location of the file with the private key</li>
            <li>When clicked, the eye icon visualizes the private key, providing an extra layer of security and ensuring you're entering the correct key.</li>
        </ol>
    </li>
    <li>Click the <strong>Sign message</strong> button.</li>
</ol>
The generated signed secret phrase will appear at the bottom of the page. Click on the Copy to clipboard line to copy it to the clipboard.

## Error Messages
- ***“Please fill in the message”*** will appear if the ***Sign message*** button is pressed when the ***Message*** field is empty
- ***“Please fill in the private key”*** will appear if the ***Sign message*** button is pressed when the ***Private key*** field is empty
- ***“Expected 64-byte private key. Please fill in the private key correctly”*** will appear if the length of the entered private key is incorrect, a message will appear.