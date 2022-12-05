# Example Workflow

This is an example workflow for enrolling custom secure boot keys on a ASUS
Z170-A motherboard. These instructions can be applied to any other firmware,
but the exact steps to be taken in the firmware setup menus may differ.

1. Enter UEFI setup menu by press either of F2/Del/Esc/F10/F11/F12 depending
on your firmware or by using `systemctl --firmware-setup reboot`

2. Open the `Boot/Secure Boot` menu:
![Boot Menu](workflow-example-images/01%20-%20Boot%20Menu.png)

3. Do not change `OS Type` to `Custom` as this will not enable `Setup Mode`!
Instead open the sub-menu `Key Management`:
![Secure Boot Menu](workflow-example-images/02%20-%20Secure%20Boot%20Menu.png)

4. Use `Clear Secure Boot Keys` to enter `Setup Mode`:
![Clear Secure Boot Keys](workflow-example-images/03%20-%20Key%20Management%20Menu.png)

5. If your firmware does not provide this, you will have to manually delete the
keys. Open `PK Management` to do so and repeat this step for KEK, DB and DBX:
![Delete PK](workflow-example-images/04%20-%20Delete%20PK.png)
![Delete PK Confirmation](workflow-example-images/05%20-%20Delete%20PK%20Confirmation.png)

6. The secure boot keys should now be cleared…
![Secure Boot Keys Cleared](workflow-example-images/06%20-%20Keys%20Cleared.png)

7. And secure boot should now be disabled. The platform key will remain loaded
until the system is rebooted.
![Secure Boot Disabled, Platform Key Loaded](workflow-example-images/07%20-%20Secure%20Boot%20Disabled,%20PK%20Loaded.png)

8. Exit the firmware with the save and reset option (even if it says no changes
have been performed). You may optionally enter the firmware setup again to
confirm:
![Secure Boot Disabled, Platform Key Unloaded](workflow-example-images/08%20-%20Secure%20Boot%20Disabled,%20PK%20Unloaded.png)

9. Confirm that setup mode is enabled:
   ```
   # sbctl status
   Installed:   ✘ Sbctl is not installed
   Setup Mode:  ✘ Enabled
   Secure Boot: ✘ Disabled
   ```

10. Create custom secure boot keys:
    ```
    # sbctl create-keys
    Created Owner UUID a9fbbdb7-a05f-48d5-b63a-08c5df45ee70
    Creating secure boot keys...✔
    Secure boot keys created!
    ```

11. Enroll custom secure boot keys:
    ```
    # sbctl enroll-keys
    Enrolling keys to EFI variables...✔
    Enrolled keys to the EFI variables!
    ```

12. Confirm that setup mode is disabled now. At this point, the device is in
secure boot mode (this may only be reflected after a reboot):
    ```
    # sbctl status
    Installed:   ✔ Sbctl is installed
    Owner GUID:  a9fbbdb7-a05f-48d5-b63a-08c5df45ee70
    Setup Mode:  ✔ Disabled
    Secure Boot: ✘ Disabled
    ```

13. **Sign your bootloader and kernels with `sbctl` before rebooting!**

13. Optionally, observe the secure boot state in the firmware menu after
rebooting:
![Secure Boot With Custom Keys](workflow-example-images/09%20-%20Secure%20Boot%20Custom%20Keys.png)
![Secure Boot Custom Keys](workflow-example-images/10%20-%20Custom%20Keys.png)

15. Confirm secure boot state after reboot:
    ```
    # sbctl status
    Installed:   ✔ Sbctl is installed
    Owner GUID:  a9fbbdb7-a05f-48d5-b63a-08c5df45ee70
    Setup Mode:  ✔ Disabled
    Secure Boot: ✔ Enabled
    ```
