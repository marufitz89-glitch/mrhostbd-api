import re
import secrets
from fastapi import APIRouter, HTTPException

router = APIRouter()

# Reserved names that users cannot claim
RESERVED_SUBDOMAINS = {
    "www",
    "api",
    "admin",
    "mail",
    "ftp",
    "smtp",
    "support",
    "help",
    "dashboard",
    "panel",
    "status",
}


def normalize_subdomain(value: str) -> str:
    """
    Convert user input into a safe subdomain slug.
    """
    value = value.strip().lower()

    # Replace anything other than letters/numbers/hyphen
    value = re.sub(r"[^a-z0-9-]", "-", value)

    # Remove repeated hyphens
    value = re.sub(r"-+", "-", value)

    # Remove hyphens from beginning/end
    value = value.strip("-")

    # Maximum DNS label length
    value = value[:63]

    return value


def generate_subdomain(project_name: str) -> str:
    """
    Generate a unique-looking subdomain.
    """

    slug = normalize_subdomain(project_name)

    if not slug:
        slug = "site"

    if slug in RESERVED_SUBDOMAINS:
        slug = f"{slug}-site"

    random_part = secrets.token_hex(3)

    return f"{slug}-{random_part}"


def get_live_url(subdomain: str) -> str:
    """
    Return the public website URL.
    """

    safe_subdomain = normalize_subdomain(subdomain)

    if not safe_subdomain:
        raise ValueError("Invalid subdomain")

    return f"https://{safe_subdomain}.mrhostbd.rf.gd"


@router.get("/generate")
async def generate_domain(project_name: str):
    """
    Generate a new subdomain.
    """

    subdomain = generate_subdomain(project_name)
    url = get_live_url(subdomain)

    return {
        "success": True,
        "subdomain": subdomain,
        "domain": f"{subdomain}.mrhostbd.rf.gd",
        "url": url
    }


@router.get("/validate/{subdomain}")
async def validate_domain(subdomain: str):
    """
    Validate a requested subdomain.
    """

    normalized = normalize_subdomain(subdomain)

    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Invalid subdomain"
        )

    if normalized in RESERVED_SUBDOMAINS:
        return {
            "success": True,
            "available": False,
            "subdomain": normalized,
            "reason": "Reserved subdomain"
        }

    return {
        "success": True,
        "available": True,
        "subdomain": normalized,
        "domain": f"{normalized}.mrhostbd.rf.gd",
        "url": f"https://{normalized}.mrhostbd.rf.gd"
    }