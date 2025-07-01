from flask import Flask, render_template, request, send_file, redirect
from stegocore import embed_files_into_image, extract_files_from_image
import io

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "cover_image" in request.files and "password" in request.form:
            cover_image = request.files["cover_image"]
            files = request.files.getlist("hidden_files")
            password = request.form["password"]
            anti_detect = request.form.get("anti_detect") == "on"

            try:
                stego_image = embed_files_into_image(cover_image, files, password, anti_detect)
                return send_file(stego_image, as_attachment=True, download_name="stego_output.png")
            except Exception as e:
                return f"<h2>Error embedding: {e}</h2><a href='/'>Back</a>"

        elif "stego_image" in request.files and "password_extract" in request.form:
            stego_image = request.files["stego_image"]
            password = request.form["password_extract"]

            try:
                zip_buffer = extract_files_from_image(stego_image, password)
                return send_file(zip_buffer, as_attachment=True, download_name="extracted_files.zip")
            except Exception as e:
                return f"<h2>Error extracting: {e}</h2><a href='/'>Back</a>"

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)