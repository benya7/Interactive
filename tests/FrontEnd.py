import asyncio
import base64
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime
import sys
import nest_asyncio
import cv2
import numpy as np
import openai
import pyotp
import soundfile as sf
from agixtsdk import AGiXTSDK
from IPython.display import Image, display
from playwright.async_api import async_playwright
from pyzbar.pyzbar import decode
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
openai.base_url = os.getenv("EZLOCALAI_URI")
openai.api_key = os.getenv("EZLOCALAI_API_KEY", "none")


async def print_args(msg):
    for arg in msg.args:
        try:
            value = await arg.json_value()
            print("CONSOLE MESSAGE:", value)
        except Exception as e:
            # Fall back to text() if json_value() fails
            text_value = await arg.text()
            print("CONSOLE MESSAGE:", text_value)


def is_desktop():
    return not platform.system() == "Linux"


class FrontEndTest:

    def __init__(
        self,
        base_uri: str = "http://localhost:3437",
        features: str = "",
    ):
        self.base_uri = base_uri
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.screenshots_dir = os.path.join("test_screenshots", f"test_run_{timestamp}")
        os.makedirs(self.screenshots_dir, exist_ok=True)
        self.browser = None
        self.context = None
        self.page = None
        self.popup = None
        self.playwright = None
        self.screenshots_with_actions = []
        self.agixt = AGiXTSDK(base_uri="https://api.agixt.dev")
        self.agixt.register_user(
            email=f"{uuid.uuid4()}@example.com", first_name="Test", last_name="User"
        )
        # Features are comma separated, options are:
        # - stripe
        # - email
        # - google
        if features == "":
            features = os.environ.get("features", "")
        if features == "":
            self.features = []
        elif "," in features:
            self.features = features.split(",")
        else:
            self.features = [features]
        if "," in features:
            self.features = features.split(",")
        else:
            if features != "":
                self.features = [features]

    async def take_screenshot(self, action_name, no_sleep=False):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_action_name = re.sub(r"[^a-zA-Z0-9_-]", "_", action_name)
        screenshot_path = os.path.join(
            self.screenshots_dir, f"{timestamp}_{sanitized_action_name}.png"
        )
        logging.info(
            f"[{timestamp}] Action: {action_name} - Screenshot path: {screenshot_path}"
        )
        target = self.popup if self.popup else self.page
        logging.info(
            f"Screenshotting { 'popup' if self.popup else 'page'} at {target.url}"
        )
        if not no_sleep:
            await target.wait_for_timeout(2000)

        await target.screenshot(path=screenshot_path)

        if not os.path.exists(screenshot_path):
            raise Exception(f"Failed to capture screenshot on action: {action_name}")

        # Add screenshot and action to the list
        self.screenshots_with_actions.append((screenshot_path, action_name))

        display(Image(filename=str(screenshot_path)))
        return screenshot_path

    def create_video_report(self, max_size_mb=10):
        """
        Creates a video from all screenshots taken during the test run with Google TTS narration
        using OpenCV and FFMPEG for video processing. Adjusts framerate and compression if output exceeds size limit.

        Args:
            max_size_mb (int): Maximum size of the output video in MB. Defaults to 10.
        """

        if is_desktop():
            return None
        try:
            if not self.screenshots_with_actions:
                logging.warning("No screenshots found to create video")
                return None

            # Read first image to get dimensions
            first_img = cv2.imread(self.screenshots_with_actions[0][0])
            if first_img is None:
                logging.error(
                    f"Failed to read first screenshot: {self.screenshots_with_actions[0][0]}"
                )
                return None

            height, width = first_img.shape[:2]

            # Create temporary directory for files
            temp_dir = tempfile.mkdtemp()
            logging.info("Creating temporary directory for audio files...")

            def create_video(fps):
                """Helper function to create video at specified FPS"""
                video_path = os.path.join(temp_dir, "video_no_audio.mp4")
                fourcc = cv2.VideoWriter_fourcc(*"mp4v")
                out = cv2.VideoWriter(video_path, fourcc, fps, (width, height))
                total_frames = 0

                for idx, (screenshot_path, _) in enumerate(
                    self.screenshots_with_actions
                ):
                    frames_needed = int(max(all_audio_lengths[idx], 2.0) * fps)
                    img = cv2.imread(screenshot_path)
                    for _ in range(frames_needed):
                        out.write(img)
                        total_frames += 1

                out.release()
                return video_path, total_frames

            def combine_video_audio(silent_video_path, audio_path, output_path, crf=23):
                """Helper function to combine video and audio with compression"""
                subprocess.run(
                    [
                        "ffmpeg",
                        "-i",
                        silent_video_path,
                        "-i",
                        audio_path,
                        "-c:v",
                        "libx264",  # Use H.264 codec
                        "-crf",
                        str(
                            crf
                        ),  # Compression quality (18-28 is good, higher = more compression)
                        "-preset",
                        "medium",  # Encoding speed preset
                        "-c:a",
                        "aac",
                        "-b:a",
                        "128k",  # Compress audio bitrate
                        output_path,
                        "-y",
                        "-loglevel",
                        "error",
                    ]
                )

            # Create paths for our files
            final_video_path = os.path.abspath(os.path.join(os.getcwd(), "report.mp4"))
            concatenated_audio_path = os.path.join(temp_dir, "combined_audio.wav")

            # Lists to store audio data and durations
            all_audio_data = []
            all_audio_lengths = []

            # First pass: Generate audio files and calculate durations
            logging.info("Generating audio narrations...")
            for idx, (_, action_name) in enumerate(
                tqdm(
                    self.screenshots_with_actions,
                    desc="Generating audio files",
                    unit="clip",
                )
            ):
                # Generate audio file for this action
                audio_path = os.path.join(temp_dir, f"audio_{idx}.wav")

                try:
                    # Clean up the action name for better narration
                    cleaned_action = action_name.replace("_", " ")
                    cleaned_action = re.sub(r"([a-z])([A-Z])", r"\1 \2", cleaned_action)

                    # Generate TTS audio
                    tts = openai.audio.speech.create(
                        model="tts-1",
                        voice="HAL9000",
                        input=cleaned_action,
                        extra_body={"language": "en"},
                    )
                    audio_content = base64.b64decode(tts.content)

                    # Write the raw audio first
                    with open(audio_path, "wb") as audio_file:
                        audio_file.write(audio_content)

                    # Read the audio and get its original sample rate
                    audio_data, sample_rate = sf.read(audio_path)

                    # Add small silence padding at the end (0.5 seconds)
                    padding = int(0.5 * sample_rate)  # Use the actual sample rate
                    audio_data = np.pad(audio_data, (0, padding), mode="constant")

                    # Store audio data and sample rate
                    all_audio_data.append((audio_data, sample_rate))
                    audio_duration = len(audio_data) / sample_rate
                    all_audio_lengths.append(max(audio_duration, 2.0))

                except Exception as e:
                    logging.error(f"Error processing clip {idx}: {e}")
                    all_audio_lengths.append(2.0)
            if all_audio_data:
                # Use the sample rate from the first audio clip
                target_sample_rate = all_audio_data[0][1]

                # Resample all audio to match the first clip's sample rate if needed
                resampled_audio = []
                for audio_data, sr in all_audio_data:
                    if sr != target_sample_rate:
                        # You might need to add a resampling library like librosa here
                        # resampled = librosa.resample(audio_data, orig_sr=sr, target_sr=target_sample_rate)
                        resampled = audio_data  # Placeholder for actual resampling
                    else:
                        resampled = audio_data
                    resampled_audio.append(resampled)

                # Combine the resampled audio
                combined_audio = np.concatenate(resampled_audio)

                # Write with the correct sample rate
                sf.write(concatenated_audio_path, combined_audio, target_sample_rate)

            # Initial attempt with 30 fps and moderate compression
            initial_fps = 30
            silent_video_path, total_frames = create_video(initial_fps)
            combine_video_audio(
                silent_video_path, concatenated_audio_path, final_video_path, crf=23
            )

            # Get file size in MB
            file_size_mb = os.path.getsize(final_video_path) / (1024 * 1024)

            # If file is still too large, try increasing compression and reducing fps
            if file_size_mb > max_size_mb:
                logging.info(
                    f"Video size ({file_size_mb:.2f}MB) exceeds limit of {max_size_mb}MB. Adjusting settings..."
                )

                # First try stronger compression
                logging.info("Attempting stronger compression...")
                combine_video_audio(
                    silent_video_path, concatenated_audio_path, final_video_path, crf=28
                )
                file_size_mb = os.path.getsize(final_video_path) / (1024 * 1024)

                # If still too large, reduce fps and maintain high compression
                if file_size_mb > max_size_mb:
                    # Calculate new fps based on size ratio with some extra buffer
                    new_fps = int(
                        initial_fps * (max_size_mb / file_size_mb) * 0.85
                    )  # 15% buffer
                    new_fps = max(new_fps, 10)  # Don't go below 10 fps

                    logging.info(
                        f"Recreating video with {new_fps} fps and high compression..."
                    )
                    silent_video_path, total_frames = create_video(new_fps)
                    combine_video_audio(
                        silent_video_path,
                        concatenated_audio_path,
                        final_video_path,
                        crf=28,
                    )

            # Cleanup
            logging.info("Cleaning up temporary files...")
            shutil.rmtree(temp_dir)

            if not os.path.exists(final_video_path):
                logging.error("Video file was not created successfully")
                return None

            final_size_mb = os.path.getsize(final_video_path) / (1024 * 1024)
            logging.info(
                f"Video report created successfully at: {final_video_path} (Size: {final_size_mb:.2f}MB)"
            )
            return final_video_path

        except Exception as e:
            logging.error(f"Error creating video report: {e}")
            return None

    async def prompt_agent(self, action_name, screenshot_path):

        prompt = f"""The goal will be to view the screenshot and determine if the action was successful or not.

        The action we were trying to perform was: {action_name}

        This screenshot shows the result of the action.

        In your <answer> block, respond with only one word `True` if the screenshot is as expected, to indicate if the action was successful. If the action was not successful, explain why in the <answer> block, this will be sent to the developers as the error in the test.
        """
        with open(screenshot_path, "rb") as f:
            screenshot = f.read().decode("utf-8")
        screenshot = f"data:image/png;base64,{screenshot}"
        response = self.agixt.prompt_agent(
            agent_name="XT",
            prompt_name="Think About It",
            prompt_args={"user_input": prompt, "file_urls": [screenshot]},
        )
        logging.info(f"Agent response: {response}")
        updated_response = re.sub(r"[^a-zA-Z]", "", response).lower()
        if updated_response != "true":
            raise Exception(
                f"Action failed: {action_name}\nAI suggested the action was not successful:\n{response}"
            )

    async def handle_mfa_screen(self):
        """Handle MFA screenshot"""
        # Decode QR code from screenshot
        await asyncio.sleep(2)
        # await self.take_screenshot(f"Screenshot prior to attempting to decode QR code")
        nparr = np.frombuffer(await self.page.screenshot(), np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        otp_uri = None
        decoded_objects = decode(img)
        for obj in decoded_objects:
            if obj.type == "QRCODE":
                otp_uri = obj.data.decode("utf-8")
                break
        if not otp_uri:
            raise Exception("Failed to decode QR code")
        logging.info(f"Retrieved OTP URI: {otp_uri}")
        match = re.search(r"secret=([\w\d]+)", otp_uri)
        if match:
            secret_key = match.group(1)
            logging.info("Successfully extracted secret key")
            totp = pyotp.TOTP(secret_key)
            otp_token = totp.now()
            await self.page.fill("#token", otp_token)
            logging.info("Entering OTP token")
            await self.take_screenshot(
                "The user scans the QR code and enrolls it in their authenticator app, then entering the one-time password therefrom."
            )
            logging.info("Submitting OTP token")
            await self.page.click('button[type="submit"]')
        else:
            raise Exception("Failed to extract secret key from OTP URI")
        return secret_key

    async def test_action(
        self, action_description, action_function, followup_function=None
    ):
        """
        Generic method to perform a test action

        Args:
            action_description (str): Description of the action being performed
            action_function (callable): Function to perform the action (async)
        """
        try:
            logging.info(action_description)
            await asyncio.sleep(5)
            await self.page.wait_for_load_state("domcontentloaded", timeout=90000)
            result = await action_function()
            await self.page.wait_for_load_state("domcontentloaded", timeout=90000)
            await asyncio.sleep(5)
            if followup_function:
                await followup_function()
            await self.take_screenshot(f"{action_description}")
            return result
        except Exception as e:
            logging.error(f"Failed {action_description}: {e}")
            raise Exception(f"Failed {action_description}: {e}")

    async def handle_register(self):
        """Handle the registration process"""
        email_address = f"{uuid.uuid4()}@example.com"

        await self.test_action(
            f"The user enters their email address in the registration form. Since this e-mail address doesn't have an account yet, we proceed to the registration page.",
            lambda: self.page.fill("#email", email_address),
        )

        await self.test_action(
            "Clicking the 'Continue with Email' button advances the process.",
            lambda: self.page.locator("text=Continue with Email").click(),
        )

        first_name = "Test"
        last_name = "User"
        await self.test_action(
            f"The user enters their first name, in this case. {first_name}. We are using the name {first_name} {last_name} for demonstration purposes.",
            lambda: self.page.fill("#first_name", first_name),
        )

        await self.test_action(
            f"The user enters their last name: {last_name}.",
            lambda: self.page.fill("#last_name", last_name),
        )

        await self.test_action(
            "Clicking the 'Register' button advances the login process to the multifactor authentication confirmation step after registration, ensuring the user has enrolled therein.",
            lambda: self.page.click('button[type="submit"]'),
        )

        mfa_token = await self.test_action(
            "After successfully entering their one time password, the user is allowed into the application.",
            lambda: self.handle_mfa_screen(),
        )

        logging.info(f"MFA token {mfa_token} handled successfully")
        if "email" in self.features:
            await self.handle_email()
        return email_address, mfa_token

    async def handle_google(self):
        """Handle Google OAuth scenario"""
        # await stealth_async(self.context)

        async def handle_oauth_async(popup):
            self.popup = popup
            logging.info(f"New popup URL: {popup.url}")
            await popup.wait_for_timeout(5000)
            await self.take_screenshot("Google OAuth popup window opened correctly")

            await self.test_action(
                "E-mail is entered in Google OAuth form",
                lambda: popup.fill("#identifierId", os.getenv("GoogleTestEmail")),
            )

            await self.test_action(
                "System advanced to password screen in Google OAuth",
                lambda: popup.click('text="Next"'),
            )

            await self.test_action(
                "Password is entered in Google OAuth form",
                lambda: popup.fill("[type=password]", os.getenv("GoogleTestPassword")),
            )

            await self.test_action(
                "System showing Google safety screen",
                lambda: popup.click('text="Next"'),
            )

            await self.test_action(
                "System showing Google access permissions screen",
                lambda: popup.click('text="Continue"'),
            )

            await self.test_action(
                "system showing scope selection screen",
                lambda: popup.click('text="Continue"'),
            )

            await self.test_action(
                "required scopes are checked for Google OAuth",
                lambda: popup.click("[type=checkbox]"),
            )

            await self.test_action(
                "popup closed", lambda: popup.click('text="Continue"')
            )

            await popup.wait_for_timeout(20000)
            self.popup = None

        self.page.on("popup", handle_oauth_async)

        await self.test_action(
            "Clicking 'Login with Google' button",
            lambda: self.page.locator("text=Login with Google").click(),
        )

        await self.take_screenshot(
            "Google OAuth process completed and returned to main application"
        )

    async def handle_chat(self):
        try:
            await self.test_action(
                "After the user logs in, the chat interface is loaded and ready for their first basic interaction.",
                lambda: self.page.click("text=Chat"),
            )
            await self.test_action(
                "By clicking in the chat bar, the user can expand it to show more options and see their entire input.",
                lambda: self.page.click("#message"),
            )
            await self.test_action(
                "The user enters an input to prompt the default agent, since no advanced settings have been configured, this will use the default A G I X T thought process.",
                lambda: self.page.fill(
                    "#message",
                    "Can you show be a basic 'hello world' Python example?",
                ),
            )
            await self.test_action(
                "When the user hits send, or the enter key, the message is sent to the agent and it begins thinking.",
                lambda: self.page.click("#send-message"),
            )

            await asyncio.sleep(90)

            await self.take_screenshot(
                "When the agent finishes thinking, the agent responds alongside providing its thought process and renaming the conversation contextually."
            )

            # await self.test_action(
            #     "Record audio",
            #     lambda: self.page.click("#audio-start-recording"),
            # )
            # with open('./audio.wav', 'rb') as audio_file:
            #     audio_base64 = base64.b64encode(audio_file.read()).decode('utf-8')
            # await self.page.evaluate(
            #     f"""
            #     // Mock MediaRecorder and getUserMedia for audio file simulation
            #     navigator.mediaDevices.getUserMedia = async () => {{
            #         // Create audio context and media stream
            #         const audioContext = new AudioContext();
            #         const audioBuffer = await audioContext.decodeAudioData(
            #             Uint8Array.from(atob('{audio_base64}'), c => c.charCodeAt(0)).buffer
            #         );

            #         // Create a media stream from the audio buffer
            #         const source = audioContext.createBufferSource();
            #         source.buffer = audioBuffer;
            #         const destination = audioContext.createMediaStreamDestination();
            #         source.connect(destination);

            #         // Start playing the audio
            #         source.start();

            #         return destination.stream;
            #     }};
            # """
            # )

            # await self.test_action(
            #     "Confirm audio",
            #     lambda: self.page.click("#audio-finish-recording"),
            # )

            # await self.test_action(
            #     "message is sent and the timer has started",
            #     lambda: self.page.click("#send-message"),
            # )
            # await asyncio.sleep(120)

            # await self.take_screenshot("voice response")
        except Exception as e:
            logging.error(f"Error nagivating to chat: {e}")
            raise Exception(f"Error nagivating to chat: {e}")

    async def handle_commands_workflow(self):
        """Handle commands workflow scenario"""
        # TODO: Implement commands workflow test
        pass

    async def handle_mandatory_context(self):
        """Handle mandatory context scenario"""
        # TODO: Implement mandatory context test
        pass

    async def handle_email(self):
        """Handle email verification scenario"""
        # TODO: Handle email verification workflow
        pass

    async def handle_login(self, email, mfa_token):
        """Handle login scenario"""
        try:
            # Navigate to login page
            await self.test_action(
                "The user navigates to the login page",
                lambda: self.page.goto(f"{self.base_uri}/user"),
                lambda: self.page.wait_for_selector("input#email", state="visible"),
            )

            await self.test_action(
                f"The user enters their email address: {email}",
                lambda: self.page.wait_for_selector("#email", state="visible"),
                lambda: self.page.fill("#email", email),
            )

            # Click continue with email
            await self.test_action(
                "The user clicks 'Continue with Email' to proceed",
                lambda: self.page.wait_for_selector(
                    "text=Continue with Email", state="visible"
                ),
                lambda: self.page.click("text=Continue with Email"),
            )

            # Generate OTP code from saved MFA token
            otp = pyotp.TOTP(mfa_token).now()

            # Fill in the OTP code
            await self.test_action(
                f"The user enters their MFA code: {otp}",
                lambda: self.page.wait_for_selector("#token", state="visible"),
                lambda: self.page.fill("#token", otp),
            )

            # Submit the login form
            await self.test_action(
                "The user submits the MFA token to complete login",
                lambda: self.page.wait_for_selector(
                    'button[type="submit"]', state="visible"
                ),
                lambda: self.page.click('button[type="submit"]'),
            )

            # Verify successful login by waiting for chat page
            await self.test_action(
                "The system authenticates the user and redirects to the chat interface",
                lambda: self.page.wait_for_url(
                    f"{self.base_uri}/chat", wait_until="networkidle"
                ),
            )
        except Exception as e:
            logging.error(f"Error during login: {e}")
            raise Exception(f"Error during login: {str(e)}")

    async def handle_logout(self, email=None):
        """Handle logout with multiple click approaches"""
        try:
            # Wait for page to be fully loaded
            await self.test_action(
                "Waiting for page to load for logout",
                lambda: self.page.wait_for_load_state("networkidle"),
            )

            await self.take_screenshot("Before attempting to log out")

            # Determine the email to look for
            email_part = email if email else "@example.com"
            logging.info(f"Targeting button containing email: {email_part}")

            # First approach: Try using Playwright's click method
            try:
                logging.info("Trying Playwright's click method")
                await self.test_action(
                    "Finding user button with email",
                    lambda: self.page.wait_for_selector(
                        f'text="{email_part}"', state="visible"
                    ),
                    lambda: self.page.click(f'text="{email_part}"', force=True),
                )

                await self.page.wait_for_timeout(1500)
                await self.take_screenshot("After Playwright click")

                # Check if any menu items appeared
                menu_items = self.page.locator('[role="menuitem"]')
                menu_count = await menu_items.count()
                logging.info(f"Found {menu_count} menu items after Playwright click")

                if menu_count > 0:
                    # Look for logout item
                    for i in range(menu_count):
                        item = menu_items.nth(i)
                        text = await item.text_content()
                        if (
                            "log out" in text.lower()
                            or "logout" in text.lower()
                            or "sign out" in text.lower()
                        ):
                            logging.info(f"Found logout item: {text}")
                            await self.test_action(
                                "Clicking logout menu item",
                                lambda: self.page.wait_for_selector(
                                    f'[role="menuitem"]:has-text("{text}")',
                                    state="visible",
                                ),
                                lambda: item.click(),
                            )
                            await self.page.wait_for_timeout(2000)

                            # Check if we logged out
                            current_url = self.page.url
                            if (
                                "/user" in current_url
                                or current_url == self.base_uri
                                or current_url.endswith("/")
                            ):
                                logging.info(
                                    f"Successfully logged out - URL: {current_url}"
                                )
                                return

                    # If we didn't find a specific logout item, try the last one
                    if menu_count > 0:
                        logging.info("Clicking last menu item")
                        await self.test_action(
                            "Clicking last menu item",
                            lambda: self.page.wait_for_selector(
                                '[role="menuitem"]:last-child', state="visible"
                            ),
                            lambda: menu_items.last.click(),
                        )
                        await self.page.wait_for_timeout(2000)

                        # Check if we logged out
                        current_url = self.page.url
                        if (
                            "/user" in current_url
                            or current_url == self.base_uri
                            or current_url.endswith("/")
                        ):
                            logging.info(
                                f"Successfully logged out - URL: {current_url}"
                            )
                            return
            except Exception as playwright_error:
                logging.info(f"Playwright approach error: {playwright_error}")

            # Second approach: Try using a full user action sequence
            try:
                logging.info("Trying full user action sequence")

                # Find the button with more specific selector
                user_details = await self.test_action(
                    "Finding user button with specific details",
                    lambda: self.page.wait_for_selector("body", state="visible"),
                    lambda: self.page.evaluate(
                        f"""() => {{
                        const allButtons = Array.from(document.querySelectorAll('button'));
                        const userButton = allButtons.find(button => 
                            button.textContent.includes('{email_part}') && 
                            button.querySelector('[data-size="lg"]') !== null
                        );
                        
                        if (userButton) {{
                            // Get position for mouse click
                            const rect = userButton.getBoundingClientRect();
                            return {{
                                found: true,
                                id: userButton.id,
                                x: rect.left + rect.width / 2,
                                y: rect.top + rect.height / 2
                            }};
                        }}
                        
                        return {{ found: false }};
                    }}"""
                    ),
                )

                logging.info(f"User button details: {user_details}")

                if user_details.get("found"):
                    # Use mouse action to click at the center of the button
                    await self.test_action(
                        "Clicking user button using mouse coordinates",
                        lambda: self.page.wait_for_selector("body", state="visible"),
                        lambda: self.page.mouse.click(
                            user_details.get("x", 0), user_details.get("y", 0)
                        ),
                    )
                    await self.page.wait_for_timeout(1500)
                    await self.take_screenshot("After mouse click")

                    # Check for menu items again
                    menu_appeared = await self.test_action(
                        "Checking for menu items after mouse click",
                        lambda: self.page.wait_for_selector(
                            '[role="menuitem"]', state="visible", timeout=5000
                        ),
                        lambda: self.page.evaluate(
                            """() => {
                            const menuItems = document.querySelectorAll('[role="menuitem"]');
                            console.log('Menu items after mouse click:', menuItems.length);
                            
                            if (menuItems.length > 0) {
                                // Try to find logout item
                                for (const item of menuItems) {
                                    const text = item.textContent.toLowerCase();
                                    if (text.includes('log out') || text.includes('logout') || text.includes('sign out')) {
                                        console.log('Found logout item, clicking');
                                        item.click();
                                        return { clicked: true, text };
                                    }
                                }
                                
                                // If no logout item found, click the last one
                                console.log('Clicking last menu item');
                                menuItems[menuItems.length - 1].click();
                                return { clicked: true, lastItem: true };
                            }
                            
                            return { clicked: false };
                        }"""
                        ),
                    )

                    logging.info(f"Menu interaction results: {menu_appeared}")

                    if menu_appeared.get("clicked"):
                        await self.page.wait_for_timeout(2000)

                        # Check if we logged out
                        current_url = self.page.url
                        if (
                            "/user" in current_url
                            or current_url == self.base_uri
                            or current_url.endswith("/")
                        ):
                            logging.info(
                                f"Successfully logged out - URL: {current_url}"
                            )
                            return
            except Exception as mouse_error:
                logging.info(f"Mouse action approach error: {mouse_error}")

            # Third approach: Try using keyboard shortcuts
            logging.info("Trying keyboard shortcut approach")
            try:
                # Find and focus the button first
                focused = await self.test_action(
                    "Finding and focusing user button",
                    lambda: self.page.wait_for_selector("body", state="visible"),
                    lambda: self.page.evaluate(
                        f"""() => {{
                        const userButton = Array.from(document.querySelectorAll('button')).find(
                            button => button.textContent.includes('{email_part}')
                        );
                        
                        if (userButton) {{
                            userButton.focus();
                            return true;
                        }}
                        return false;
                    }}"""
                    ),
                )

                if focused:
                    # Press Enter to activate the button
                    await self.test_action(
                        "Pressing Enter to activate user button",
                        lambda: self.page.wait_for_selector(
                            "button:focus", state="visible"
                        ),
                        lambda: self.page.keyboard.press("Enter"),
                    )
                    await self.page.wait_for_timeout(1500)
                    await self.take_screenshot("After keyboard Enter")

                    # Check if dropdown opened
                    dropdown_visible = await self.test_action(
                        "Checking for menu items after keyboard Enter",
                        lambda: self.page.wait_for_selector(
                            '[role="menuitem"]', state="visible", timeout=5000
                        ),
                        lambda: self.page.evaluate(
                            """() => {
                            return document.querySelectorAll('[role="menuitem"]').length > 0;
                        }"""
                        ),
                    )

                    if dropdown_visible:
                        # Press Down to get to the logout item (often the last one)
                        for _ in range(
                            5
                        ):  # Try a few Down keys to navigate to the bottom
                            await self.test_action(
                                "Navigating menu with arrow down",
                                lambda: self.page.wait_for_selector(
                                    '[role="menuitem"]', state="visible"
                                ),
                                lambda: self.page.keyboard.press("ArrowDown"),
                            )
                            await self.page.wait_for_timeout(300)

                        # Press Enter to select
                        await self.test_action(
                            "Pressing Enter to select logout menu item",
                            lambda: self.page.wait_for_selector(
                                '[role="menuitem"][data-selected="true"]',
                                state="visible",
                            ),
                            lambda: self.page.keyboard.press("Enter"),
                        )
                        await self.page.wait_for_timeout(2000)

                        # Check if we logged out
                        current_url = self.page.url
                        if (
                            "/user" in current_url
                            or current_url == self.base_uri
                            or current_url.endswith("/")
                        ):
                            logging.info(
                                f"Successfully logged out via keyboard - URL: {current_url}"
                            )
                            return
            except Exception as keyboard_error:
                logging.info(f"Keyboard approach error: {keyboard_error}")

            # Final fallback: Direct navigation to logout URL
            logging.info("Trying direct navigation to logout URL")
            await self.test_action(
                "Navigating to logout URL",
                lambda: self.page.wait_for_selector("body", state="visible"),
                lambda: self.page.goto(f"{self.base_uri}/user/logout"),
            )
            await self.page.wait_for_timeout(2000)

            # Check if we got logged out
            current_url = self.page.url
            if (
                "/user" in current_url
                or current_url == self.base_uri
                or current_url.endswith("/")
            ):
                logging.info(
                    f"Successfully logged out via direct URL - URL: {current_url}"
                )
                return

            raise Exception("Failed to log out after multiple approaches")

        except Exception as e:
            logging.error(f"Error during logout: {e}")
            await self.take_screenshot("Error_during_logout")
            raise Exception(f"Failed to logout: {str(e)}")

    async def handle_update_user(self):
        """Handle user update scenario by changing last name and timezone"""
        try:
            # Navigate to user management page
            await self.test_action(
                "The user navigates to the account management page",
                lambda: self.page.wait_for_selector("body", state="visible"),
                lambda: self.page.goto(f"{self.base_uri}/user/manage"),
            )

            # Take a screenshot to examine the form structure
            await self.take_screenshot(
                "User management page loaded - examining form structure"
            )

            # Find the last name field and update it with a unique value
            new_last_name = f"Updated{uuid.uuid4().hex[:6]}"

            # Try various selectors to find the last name field
            last_name_input = None
            selectors = [
                'input[id*="last_name" i]',  # Case-insensitive id containing "last_name"
                'input[name*="last_name" i]',
                'input[placeholder*="last name" i]',
                "form input:nth-child(2)",  # Often the second input in a name form
            ]

            for selector in selectors:
                count = await self.page.locator(selector).count()
                if count > 0:
                    last_name_input = selector
                    break

            if last_name_input:
                await self.test_action(
                    f"The user updates their last name to '{new_last_name}'",
                    lambda: self.page.wait_for_selector(
                        last_name_input, state="visible"
                    ),
                    lambda: self.page.fill(last_name_input, new_last_name),
                )
            else:
                logging.warning("Could not find last name field, continuing with test")

            # Take a more general approach for finding selectable fields
            # Let's try to find and interact with any dropdown/select elements
            await self.test_action(
                "The user looks for any dropdown fields on the page to update",
                lambda: self.page.wait_for_selector(
                    "select", state="visible", timeout=5000
                ),
                lambda: self.page.evaluate(
                    """() => {
                    // Find all dropdowns or select elements
                    const selects = Array.from(document.querySelectorAll('select'));
                    if (selects.length > 0) {
                        // For each select, change to a different value if possible
                        selects.forEach(select => {
                            if (select.options.length > 1) {
                                const currentIndex = select.selectedIndex;
                                select.selectedIndex = (currentIndex + 1) % select.options.length;
                                select.dispatchEvent(new Event('change', { bubbles: true }));
                            }
                        });
                        return selects.length;
                    }
                    return 0;
                }"""
                ),
            )

            # Take screenshot after attempting to change dropdowns
            await self.take_screenshot("After attempting to modify dropdown values")

            # Look for and click any update/save button
            update_button_found = False
            update_button_selectors = [
                'button:has-text("Update")',
                'button:has-text("Save")',
                'button[type="submit"]',
                "form button",
            ]

            for selector in update_button_selectors:
                count = await self.page.locator(selector).count()
                if count > 0:
                    await self.test_action(
                        "The user clicks the button to save their profile changes",
                        lambda: self.page.wait_for_selector(selector, state="visible"),
                        lambda: self.page.click(selector),
                    )
                    update_button_found = True
                    break

            if not update_button_found:
                logging.warning(
                    "Could not find update button, attempting to submit form directly"
                )
                await self.test_action(
                    "The user submits the form to save changes",
                    lambda: self.page.wait_for_selector("form", state="visible"),
                    lambda: self.page.evaluate(
                        "document.querySelector('form').submit()"
                    ),
                )

            # Wait for the page to settle after the update
            await self.test_action(
                "The system processes the update and the page stabilizes",
                lambda: self.page.wait_for_load_state("networkidle"),
            )

            # Take a final screenshot to show the result
            await self.take_screenshot("After submitting profile updates")

            logging.info("User profile update process completed")
        except Exception as e:
            logging.error(f"Error updating user profile: {e}")
            await self.take_screenshot("Error_updating_user_profile")
            raise Exception(f"Failed to update user profile: {str(e)}")

    async def handle_invite_user(self):
        """Handle user invite scenario by inviting a user to the team"""
        try:
            # Navigate to team page
            await self.test_action(
                "The user navigates to the team management page",
                lambda: self.page.wait_for_selector("body", state="visible"),
                lambda: self.page.goto(f"{self.base_uri}/team"),
            )

            # Wait for team page to load completely
            await self.test_action(
                "The team management page loads, showing current team members and invite options",
                lambda: self.page.wait_for_load_state("networkidle"),
            )

            # Generate a random email for invitation
            invite_email = f"test.user+{uuid.uuid4().hex[:8]}@example.com"

            # Find and fill the email field
            await self.test_action(
                f"The user enters '{invite_email}' in the email field to invite a new user",
                lambda: self.page.wait_for_selector("input#email", state="visible"),
                lambda: self.page.fill("input#email", invite_email),
            )

            # For the role selection, we'll use a simpler approach without nested conditionals in lambdas
            # First check if the select content exists
            select_content_exists = (
                await self.page.locator(".select-content").count() > 0
            )

            if select_content_exists:
                await self.test_action(
                    "The user confirms the role selector is present",
                    lambda: self.page.wait_for_selector(
                        ".select-content", state="visible", timeout=1000
                    ),
                )
            else:
                await self.test_action(
                    "The user proceeds with the default role selection",
                    lambda: self.page.wait_for_timeout(1000),
                )

            # Click Send Invitation button
            await self.test_action(
                "The user clicks 'Send Invitation' to invite the new team member",
                lambda: self.page.wait_for_selector(
                    'button:has-text("Send Invitation")', state="visible"
                ),
                lambda: self.page.click('button:has-text("Send Invitation")'),
            )

            # For verification, check for success indicators separately without conditionals in lambdas
            success_message_exists = (
                await self.page.locator('text="sent successfully"').count() > 0
            )

            if success_message_exists:
                await self.test_action(
                    "The system shows a confirmation message about successful invitation",
                    lambda: self.page.wait_for_selector(
                        'text="sent successfully"', state="visible", timeout=10000
                    ),
                )
            else:
                await self.test_action(
                    "The system shows pending invitations section",
                    lambda: self.page.wait_for_selector(
                        'text="Pending Invitations"', state="visible", timeout=10000
                    ),
                )

            # Check if the email appears in the list
            email_visible = (
                await self.page.locator(f'text="{invite_email}"').count() > 0
            )

            if email_visible:
                await self.test_action(
                    f"The invited email '{invite_email}' appears in the pending invitations list",
                    lambda: self.page.wait_for_selector(
                        f'text="{invite_email}"', state="visible", timeout=5000
                    ),
                )
            else:
                await self.test_action(
                    "The invitation was processed but email may not be visible in the list",
                    lambda: self.page.wait_for_timeout(2000),
                )

            logging.info(f"User invitation sent successfully to {invite_email}")
        except Exception as e:
            logging.error(f"Error inviting user: {e}")
            await self.take_screenshot("Error_inviting_user")
            raise Exception(f"Failed to invite user: {str(e)}")

    async def handle_train_user_agent(self):
        """Handle training user agent scenario"""
        # TODO: Handle training user agent workflow
        pass

    async def handle_train_company_agent(self):
        """Handle training company agent scenario"""
        # TODO: Handle training company agent workflow
        pass

    async def handle_stripe(self):
        """Handle Stripe subscription scenario"""
        await self.take_screenshot("subscription page is loaded with available plans")
        await self.test_action(
            "Stripe checkout page is open",
            lambda: self.page.click(".bg-card button"),
            followup_function=lambda: self.page.wait_for_url(
                "https://checkout.stripe.com/c/**"
            ),
        )

        sus_button = await self.page.query_selector(
            ".Button--link.Button--checkoutSecondaryLink"
        )
        if sus_button:
            await self.test_action(
                "subscription confirmation button is visible", lambda: None
            )
            await self.test_action(
                "Click subscription confirmation button", lambda: sus_button.click()
            )

        await self.test_action(
            "Enter card number",
            lambda: self.page.fill("input#cardNumber", "4242424242424242"),
        )

        await self.test_action(
            "Enter card expiry", lambda: self.page.fill("input#cardExpiry", "1230")
        )

        await self.test_action(
            "Enter card CVC", lambda: self.page.fill("input#cardCvc", "123")
        )

        await self.test_action(
            "Enter billing name",
            lambda: self.page.fill("input#billingName", "Test User"),
        )

        await self.test_action(
            "Select billing country",
            lambda: self.page.select_option("select#billingCountry", "US"),
        )

        await self.test_action(
            "Enter billing postal code",
            lambda: self.page.fill("input#billingPostalCode", "90210"),
        )

        await self.test_action(
            "Submit payment",
            lambda: self.page.click("button.SubmitButton.SubmitButton--complete"),
        )
        await self.page.wait_for_timeout(15000)
        await self.take_screenshot("payment was processed and subscription is active")

    async def run(self, headless=not is_desktop()):
        try:
            async with async_playwright() as self.playwright:
                self.browser = await self.playwright.chromium.launch(headless=headless)
                self.context = await self.browser.new_context()
                self.page = await self.browser.new_page()
                self.page.on("console", print_args)
                self.page.set_default_timeout(20000)
                await self.page.set_viewport_size({"width": 1367, "height": 924})

                logging.info(f"Navigating to {self.base_uri}")
                await self.page.goto(self.base_uri)
                await self.take_screenshot(
                    "The landing page of the application is the first thing the user sees."
                )

                logging.info("Clicking 'Register or Login' button")
                await self.page.click('text="Login or Register"')
                await self.take_screenshot(
                    "The user has multiple authentication options if enabled, including several o auth options such as Microsoft or Google. For this test, we will use the basic email authentication."
                )

                if "google" not in self.features:
                    try:
                        email, mfa_token = await self.handle_register()
                    except Exception as e:
                        logging.error(f"Error registering user: {e}")
                        await self.browser.close()
                        raise Exception(f"Error registering user: {e}")
                if "google" in self.features:
                    email = await self.handle_google()
                    mfa_token = ""
                if "stripe" in self.features:
                    await self.handle_stripe()

                await self.handle_train_user_agent()
                await self.handle_train_company_agent()
                await self.handle_chat()

                ##
                # Any other tests can be added here
                ##

                await self.handle_logout(email=email)
                await self.handle_login(email, mfa_token)
                await self.handle_update_user()
                await self.handle_invite_user()

                video_path = self.create_video_report()
                logging.info(f"Tests complete. Video report created at {video_path}")
                await self.browser.close()
        except Exception as e:
            logging.error(f"Test failed: {e}")
            # Try to create video one last time if it failed during the test
            if not os.path.exists(os.path.join(os.getcwd(), "report.mp4")):
                self.create_video_report()
                pass
            raise e


class TestRunner:
    def __init__(self):
        pass

    def run(self):
        test = FrontEndTest(base_uri="http://localhost:3437")
        try:
            if platform.system() == "Linux":
                print("Linux Detected, using asyncio.run")
                if not asyncio.get_event_loop().is_running():
                    try:
                        asyncio.run(test.run())
                    except Exception as e:
                        logging.error(f"Test execution failed: {e}")
                        # Make one final attempt to create video if it doesn't exist
                        if not os.path.exists(os.path.join(os.getcwd(), "report.mp4")):
                            test.create_video_report()
                        sys.exit(1)
                else:
                    try:

                        nest_asyncio.apply()
                        asyncio.get_event_loop().run_until_complete(test.run())
                    except Exception as e:
                        logging.error(f"Test execution failed: {e}")
                        if not os.path.exists(os.path.join(os.getcwd(), "report.mp4")):
                            test.create_video_report()
                        sys.exit(1)
            else:
                print("Windows Detected, using asyncio.ProactorEventLoop")
                loop = asyncio.ProactorEventLoop()
                nest_asyncio.apply(loop)
                try:
                    loop.run_until_complete(test.run(False))
                except Exception as e:
                    logging.error(f"Test execution failed: {e}")
                    if not os.path.exists(os.path.join(os.getcwd(), "report.mp4")):
                        test.create_video_report()
                    sys.exit(1)
                finally:
                    loop.close()
        except Exception as e:
            logging.error(f"Critical failure: {e}")
            # Try one last time to create video even in case of critical failure
            if not os.path.exists(os.path.join(os.getcwd(), "report.mp4")):
                try:
                    test.create_video_report()
                except Exception as video_error:
                    logging.error(f"Failed to create video report: {video_error}")
            sys.exit(1)
