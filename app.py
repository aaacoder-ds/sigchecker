import io
import os
from flask import Flask, render_template, request, send_from_directory

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


app = Flask(__name__, static_folder="static", static_url_path="/static")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/verify", methods=["POST"]) 
def verify():
    uploaded = request.files.get("pdf")
    if not uploaded or uploaded.filename == "":
        return render_template("result.html", error="No PDF uploaded."), 400

    try:
        file_bytes = uploaded.read()
        pdf_stream = io.BytesIO(file_bytes)
        reader = PdfFileReader(pdf_stream)

        signatures = getattr(reader, "embedded_signatures", [])
        if not signatures:
            return render_template("result.html", results=[], message="No signatures found in the document.")

        vc = ValidationContext(allow_fetching=True)
        results = []
        for embedded_sig in signatures:
            status = validate_pdf_signature(embedded_sig, validation_context=vc)
            result = {
                "integrity_ok": getattr(status, "intact", None),
                "trust_ok": getattr(status, "trust_ok", None),
                "summary": getattr(status, "summary", lambda: "")(),
                "details": getattr(status, "pretty_print_details", lambda: "")(),
            }
            results.append(result)

        return render_template("result.html", results=results, filename=uploaded.filename)
    except Exception as e:
        return render_template("result.html", error=f"Verification failed: {e}")


@app.errorhandler(404)
def not_found(_):
    return render_template("404.html"), 404


@app.route("/robots.txt")
def robots():
    return send_from_directory(app.static_folder, "robots.txt")


@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory(app.static_folder, "sitemap.xml")


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
