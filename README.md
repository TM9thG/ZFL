# File Lock

This is a small Windows PowerShell/Windows Forms app. Double-click `start-file-lock.bat` to launch it. If Windows reports that it cannot change a file's permissions, close the app, right-click the launcher, and choose **Run as administrator**.

Enter the passcode `TM9thG` to open the app. Paste an absolute file path (or use **Browse...**), enter the message, and click **Save lock**. This adds a Windows permission rule denying the current Windows account read, write, and execute access to that file. To see your custom warning, select the saved path inside File Lock and click **Show saved message in app**. To unlock a file, select it and click **Remove lock**.

Paths saved by an earlier version are upgraded to Windows permission locks the next time the app opens.

## Important limitation

Windows and other programs show their normal access-denied behavior when they try to open or run a locked file; they cannot show the custom message. The app does not monitor open attempts, close programs already running, or protect against an administrator or someone who can change the file's permissions. File deletion may still be allowed by the containing folder's permissions. Removing a lock removes only the exact permission rule File Lock added, leaving other permission rules intact. Only files can be selected; avoid locking Windows or other system-critical files.

The passcode is included in the script as requested and is not a secure authentication mechanism. The path list, messages, and rule metadata are stored in `%LOCALAPPDATA%\TM9thGFileLock\locks.json` and read as UTF-8 so paths with non-English characters remain usable. The launcher uses a process-only PowerShell execution-policy override; it does not change the system policy.
