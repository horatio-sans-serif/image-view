#!/usr/bin/env python3
import sys
import os
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QLabel,
    QScrollArea,
    QStatusBar,
    QMessageBox,
)
from PyQt6.QtGui import QImage, QPixmap, QTransform, QCursor
from PyQt6.QtCore import Qt, QSize, QPoint, QTimer
from PyQt6.QtWidgets import QGestureRecognizer
from PIL import Image
from PIL.ExifTags import TAGS
import io


class ImageViewer(QMainWindow):
    def __init__(self, encrypted_files):
        super().__init__()
        self.files = encrypted_files
        self.current_idx = 0
        self.gpg = None  # Lazy initialization when needed
        self.zoom_factor = 1.0
        self.rotation_angle = 0
        self.fit_mode = True  # True = fit to window, False = actual size
        self.image_cache = {}  # Cache for preloaded images
        self.exif_data = {}  # Store EXIF data for current image
        self.dragging = False
        self.last_mouse_pos = QPoint()
        self.slideshow_active = False
        self.slideshow_timer = QTimer()
        self.slideshow_timer.timeout.connect(lambda: self.next_image(1))
        self.help_visible = False

        # Setup UI
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(False)  # Changed for panning
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        self.label = QLabel()
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setMouseTracking(True)
        self.scroll_area.setWidget(self.label)
        self.setCentralWidget(self.scroll_area)

        # Help overlay
        self.help_label = QLabel(self)
        self.help_label.setStyleSheet(
            "QLabel { background-color: rgba(0, 0, 0, 180); color: white; "
            "padding: 20px; font-family: monospace; }"
        )
        self.help_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.help_label.hide()

        # Info overlay
        self.info_label = QLabel(self)
        self.info_label.setStyleSheet(
            "QLabel { background-color: rgba(0, 0, 0, 180); color: white; "
            "padding: 20px; font-family: monospace; }"
        )
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.info_label.hide()

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.setGeometry(100, 100, 1024, 768)

        # Enable pinch gesture
        self.grabGesture(Qt.GestureType.PinchGesture)

        self.setup_shortcuts()
        self.load_current_image()
        self.preload_adjacent_images()

    def setup_shortcuts(self):
        self.shortcuts = {
            Qt.Key.Key_Left: lambda: self.next_image(-1),
            Qt.Key.Key_Right: lambda: self.next_image(1),
            Qt.Key.Key_PageUp: lambda: self.next_image(-1),
            Qt.Key.Key_PageDown: lambda: self.next_image(1),
            Qt.Key.Key_Home: self.go_to_first,
            Qt.Key.Key_End: self.go_to_last,
            Qt.Key.Key_Escape: self.handle_escape,
            Qt.Key.Key_R: self.rotate_image,
            Qt.Key.Key_0: self.reset_zoom,
            Qt.Key.Key_F: self.toggle_fit_mode,
            Qt.Key.Key_F11: self.toggle_fullscreen,
            Qt.Key.Key_H: self.toggle_help,
            Qt.Key.Key_Question: self.toggle_help,
            Qt.Key.Key_I: self.toggle_info,
            Qt.Key.Key_F1: self.toggle_info,
            Qt.Key.Key_S: self.toggle_slideshow,
            Qt.Key.Key_Space: self.toggle_slideshow,
        }

    def keyReleaseEvent(self, event):
        key = event.key()

        if key == Qt.Key.Key_Plus or key == Qt.Key.Key_Equal:
            self.zoom_factor *= 1.2
            self.fit_mode = False
            self.update_display()
            return

        if key == Qt.Key.Key_Minus:
            self.zoom_factor *= 0.8
            self.fit_mode = False
            self.update_display()
            return

        if key in self.shortcuts:
            self.shortcuts[key]()

    def wheelEvent(self, event):
        if event.angleDelta().y() > 0:
            self.zoom_factor *= 1.1
        else:
            self.zoom_factor *= 0.9
        self.fit_mode = False
        self.update_display()

    def event(self, event):
        if event.type() == event.Type.Gesture:
            return self.gestureEvent(event)
        return super().event(event)

    def gestureEvent(self, event):
        from PyQt6.QtWidgets import QGesture

        pinch = event.gesture(Qt.GestureType.PinchGesture)
        if pinch:
            self.pinchTriggered(pinch)
        return True

    def pinchTriggered(self, gesture):
        from PyQt6.QtWidgets import QGesture

        if gesture.state() == Qt.GestureState.GestureUpdated:
            scale_factor = gesture.scaleFactor()
            self.zoom_factor *= scale_factor
            self.fit_mode = False
            self.update_display()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = True
            self.last_mouse_pos = event.pos()
            self.setCursor(QCursor(Qt.CursorShape.ClosedHandCursor))

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = False
            self.setCursor(QCursor(Qt.CursorShape.ArrowCursor))

    def mouseMoveEvent(self, event):
        if self.dragging:
            delta = event.pos() - self.last_mouse_pos
            self.last_mouse_pos = event.pos()

            h_bar = self.scroll_area.horizontalScrollBar()
            v_bar = self.scroll_area.verticalScrollBar()

            h_bar.setValue(h_bar.value() - delta.x())
            v_bar.setValue(v_bar.value() - delta.y())

    def decrypt_image(self, source):
        try:
            # Handle stdin data (tuple) vs file path (string)
            if isinstance(source, tuple) and source[0] == 'stdin':
                # stdin contains already-decrypted image data
                image_data = source[1]
            elif os.path.isfile(source) and (source.endswith('.gpg') or source.endswith('.pgp')):
                # Decrypt from encrypted file - initialize GPG if needed
                if self.gpg is None:
                    import gnupg
                    # Try to find gpg binary
                    gpg_path = None
                    for path in ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg"]:
                        if os.path.exists(path):
                            gpg_path = path
                            break
                    if gpg_path:
                        self.gpg = gnupg.GPG(gpgbinary=gpg_path)
                    else:
                        self.gpg = gnupg.GPG()

                with open(source, "rb") as f:
                    decrypted_data = self.gpg.decrypt_file(f)
                    if not decrypted_data.ok:
                        raise Exception(f"Decryption failed: {decrypted_data.status}")
                    image_data = decrypted_data.data
            else:
                # Read directly (unencrypted file or FIFO with decrypted data)
                with open(source, "rb") as f:
                    image_data = f.read()

            # Extract EXIF data using PIL
            try:
                pil_image = Image.open(io.BytesIO(image_data))
                exif = pil_image.getexif()
                if exif:
                    self.exif_data = {
                        TAGS.get(tag, tag): value for tag, value in exif.items() if tag in TAGS
                    }
                else:
                    self.exif_data = {}
            except Exception:
                self.exif_data = {}

            return QImage.fromData(image_data)
        except Exception as e:
            self.show_error(f"Failed to load image: {str(e)}")
            return None

    def reset_zoom(self):
        self.zoom_factor = 1.0
        self.fit_mode = True
        self.update_display()

    def rotate_image(self):
        if self.label.pixmap():
            self.rotation_angle = (self.rotation_angle + 90) % 360
            self.update_display()

    def toggle_fit_mode(self):
        self.fit_mode = not self.fit_mode
        if self.fit_mode:
            self.zoom_factor = 1.0
        self.update_display()

    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def handle_escape(self):
        if self.help_visible:
            self.toggle_help()
        elif self.info_label.isVisible():
            self.toggle_info()
        elif self.slideshow_active:
            self.toggle_slideshow()
        elif self.isFullScreen():
            self.showNormal()
        else:
            self.close()

    def toggle_help(self):
        self.help_visible = not self.help_visible
        if self.help_visible:
            help_text = """KEYBOARD SHORTCUTS

Navigation:
  Left/Right Arrow    Previous/Next image
  Page Up/Down        Previous/Next image
  Home                First image
  End                 Last image

View Controls:
  +/=                 Zoom in
  -                   Zoom out
  0                   Reset zoom (fit to window)
  F                   Toggle fit mode
  R                   Rotate 90 degrees clockwise
  Mouse Wheel         Zoom in/out
  Click + Drag        Pan image

Display:
  F11                 Toggle fullscreen
  H or ?              Toggle this help
  I or F1             Toggle image info

Slideshow:
  S or Space          Start/stop slideshow

Other:
  Escape              Close help/info/slideshow/fullscreen/app
"""
            self.help_label.setText(help_text)
            self.help_label.setGeometry(self.rect())
            self.help_label.show()
            self.help_label.raise_()
        else:
            self.help_label.hide()

    def toggle_info(self):
        if self.info_label.isVisible():
            self.info_label.hide()
        else:
            self.show_image_info()

    def show_image_info(self):
        if not hasattr(self, "current_image") or self.current_image is None:
            return

        current_source = self.files[self.current_idx]
        if isinstance(current_source, tuple) and current_source[0] == 'stdin':
            filename = 'stdin'
            filesize_str = 'N/A'
        else:
            filename = os.path.basename(current_source)
            filesize = os.path.getsize(current_source)
            filesize_str = f"{filesize / 1024:.1f} KB"

        width = self.current_image.width()
        height = self.current_image.height()

        info_text = f"""IMAGE INFORMATION

File: {filename}
Size: {filesize_str}
Resolution: {width} x {height} pixels
Rotation: {self.rotation_angle} degrees
"""

        if self.exif_data:
            info_text += "\nEXIF DATA:\n"
            for key, value in sorted(self.exif_data.items()):
                # Truncate long values
                value_str = str(value)
                if len(value_str) > 50:
                    value_str = value_str[:47] + "..."
                info_text += f"  {key}: {value_str}\n"

        self.info_label.setText(info_text)
        self.info_label.setGeometry(self.rect())
        self.info_label.show()
        self.info_label.raise_()

    def toggle_slideshow(self):
        self.slideshow_active = not self.slideshow_active
        if self.slideshow_active:
            self.slideshow_timer.start(3000)  # 3 seconds per image
            self.update_status_bar()
        else:
            self.slideshow_timer.stop()
            self.update_status_bar()

    def go_to_first(self):
        self.current_idx = 0
        self.zoom_factor = 1.0
        self.fit_mode = True
        self.load_current_image()
        self.preload_adjacent_images()

    def go_to_last(self):
        self.current_idx = len(self.files) - 1
        self.zoom_factor = 1.0
        self.fit_mode = True
        self.load_current_image()
        self.preload_adjacent_images()

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)

    def update_display(self):
        if not hasattr(self, "current_image") or self.current_image is None:
            return

        pixmap = QPixmap.fromImage(self.current_image)
        transform = QTransform().rotate(self.rotation_angle)
        pixmap = pixmap.transformed(transform, Qt.TransformationMode.SmoothTransformation)

        if self.fit_mode:
            viewport_size = self.scroll_area.viewport().size()
            w_scale = viewport_size.width() / pixmap.width()
            h_scale = viewport_size.height() / pixmap.height()
            base_scale = min(w_scale, h_scale)
            final_scale = base_scale * self.zoom_factor
        else:
            final_scale = self.zoom_factor

        scaled_size = QSize(int(pixmap.width() * final_scale), int(pixmap.height() * final_scale))

        scaled = pixmap.scaled(
            scaled_size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )

        self.label.setPixmap(scaled)
        self.label.resize(scaled.size())
        self.update_status_bar()

    def update_status_bar(self):
        current_source = self.files[self.current_idx]
        if isinstance(current_source, tuple) and current_source[0] == 'stdin':
            filename = 'stdin'
        else:
            filename = os.path.basename(current_source)

        status = f"[{self.current_idx + 1}/{len(self.files)}] {filename} | Zoom: {self.zoom_factor * 100:.0f}%"

        if not self.fit_mode:
            status += " (Actual Size)"

        if self.slideshow_active:
            status += " | SLIDESHOW"

        self.status_bar.showMessage(status)

    def update_window_title(self):
        current_source = self.files[self.current_idx]
        if isinstance(current_source, tuple) and current_source[0] == 'stdin':
            filename = 'stdin'
        else:
            filename = os.path.basename(current_source)
        self.setWindowTitle(f"{filename} - Secure Image Viewer")

    def load_current_image(self):
        # Try to load from cache first
        cache_key = self.files[self.current_idx]
        if cache_key in self.image_cache:
            self.current_image = self.image_cache[cache_key]
        else:
            self.current_image = self.decrypt_image(self.files[self.current_idx])
            if self.current_image:
                self.image_cache[cache_key] = self.current_image

        if self.current_image:
            self.update_display()
            self.update_window_title()

    def next_image(self, direction):
        self.current_idx = (self.current_idx + direction) % len(self.files)
        self.zoom_factor = 1.0
        self.fit_mode = True
        self.load_current_image()
        self.preload_adjacent_images()

    def preload_adjacent_images(self):
        # Preload next and previous images in cache
        for offset in [-1, 1]:
            idx = (self.current_idx + offset) % len(self.files)
            cache_key = self.files[idx]
            if cache_key not in self.image_cache:
                try:
                    image = self.decrypt_image(self.files[idx])
                    if image:
                        self.image_cache[cache_key] = image
                        # Limit cache size to 5 images
                        if len(self.image_cache) > 5:
                            # Remove oldest (first) item
                            oldest_key = next(iter(self.image_cache))
                            del self.image_cache[oldest_key]
                except Exception:
                    pass  # Silently fail for preloading

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "help_label"):
            self.help_label.setGeometry(self.rect())
        if hasattr(self, "info_label"):
            self.info_label.setGeometry(self.rect())
        if self.fit_mode:
            self.update_display()


def main():
    files = []

    # If file arguments provided, use those
    if len(sys.argv) > 1:
        files.extend(sys.argv[1:])
    # Otherwise, check if data is being piped via stdin
    elif not sys.stdin.isatty():
        try:
            stdin_data = sys.stdin.buffer.read()
            if stdin_data:
                files.append(('stdin', stdin_data))
        except KeyboardInterrupt:
            print("\nInterrupted")
            sys.exit(1)

    if not files:
        print("Usage: simple-image-viewer [FILES]")
        print("       or pipe encrypted data via stdin")
        sys.exit(1)

    app = QApplication(sys.argv)
    viewer = ImageViewer(files)
    viewer.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
