"""LinkedIn OAuth 2.0 service."""

import os
import secrets
import hashlib
import base64
from typing import Dict, Optional
from datetime import datetime, timedelta
import httpx
from dotenv import load_dotenv

load_dotenv()


class LinkedInOAuthService:
    """Handle LinkedIn OAuth 2.0 flow."""
    
    def __init__(self):
        self.client_id = os.getenv("LINKEDIN_CLIENT_ID")
        self.client_secret = os.getenv("LINKEDIN_CLIENT_SECRET")
        self.redirect_uri = os.getenv("LINKEDIN_REDIRECT_URI", "http://localhost:8000/api/auth/linkedin/callback")
        
        # LinkedIn OAuth 2.0 endpoints
        self.auth_url = "https://www.linkedin.com/oauth/v2/authorization"
        self.token_url = "https://www.linkedin.com/oauth/v2/accessToken"
        self.user_info_url = "https://api.linkedin.com/v2/userinfo"
        self.post_url = "https://api.linkedin.com/v2/ugcPosts"
        
        # OAuth scopes
        self.scopes = [
            "openid",
            "profile",
            "email",
            "w_member_social"
        ]
    
    def get_authorization_url(self, state: str) -> tuple[str, str]:
        """
        Generate LinkedIn authorization URL.
        
        Args:
            state: Random state parameter for CSRF protection
            
        Returns:
            tuple: (auth_url, state)
        """
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
        }
        
        # Build URL
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        auth_url = f"{self.auth_url}?{query_string}"
        
        return auth_url, state
    
    async def exchange_code_for_token(self, code: str) -> Dict:
        """
        Exchange authorization code for access token.
        
        Args:
            code: Authorization code from LinkedIn
            
        Returns:
            dict: Token response with access_token, expires_in, etc.
        """
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                raise Exception(f"Token exchange failed: {response.text}")
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> Dict:
        """
        Get LinkedIn user information.
        
        Args:
            access_token: Valid access token
            
        Returns:
            dict: User information
        """
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.user_info_url,
                headers=headers
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get user info: {response.text}")
            
            return response.json()
    
    async def post_content(self, content: str, access_token: str, user_urn: str) -> Dict:
        """
        Post content to LinkedIn.
        
        Args:
            content: Text content to post
            access_token: Valid access token
            user_urn: LinkedIn user URN (e.g., "urn:li:person:...")
            
        Returns:
            dict: Post response
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0"
        }
        
        # Construct the UGC Post body
        # See: https://learn.microsoft.com/en-us/linkedin/marketing/integrations/community-management/shares/ugc-post-api
        data = {
            "author": f"urn:li:person:{user_urn}",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {
                        "text": content
                    },
                    "shareMediaCategory": "NONE"
                }
            },
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
            }
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.post_url,
                headers=headers,
                json=data
            )
            
            if response.status_code not in [200, 201]:
                raise Exception(f"Failed to post to LinkedIn: {response.text}")
            
            result = response.json()
            
            # Extract post ID (urn:li:share:...)
            post_urn = result.get("id")
            
            # Construct post URL (approximate, as API doesn't return direct URL)
            # Usually https://www.linkedin.com/feed/update/{post_urn}
            url = f"https://www.linkedin.com/feed/update/{post_urn}" if post_urn else None
            
            return {
                "post_id": post_urn,
                "url": url,
                "raw_response": result
            }
            
    def calculate_token_expiry(self, expires_in: int) -> datetime:
        """
        Calculate token expiration datetime.
        
        Args:
            expires_in: Seconds until expiration
            
        Returns:
            datetime: Expiration time (timezone-aware UTC)
        """
        from datetime import timezone
        return datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    
    def is_token_expired(self, expires_at: datetime) -> bool:
        """
        Check if token is expired.
        
        Args:
            expires_at: Token expiration datetime
            
        Returns:
            bool: True if expired
        """
        from datetime import timezone
        
        # Ensure both datetimes are timezone-aware
        now = datetime.now(timezone.utc)
        
        # If expires_at is naive, assume UTC
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        
        # Add 5 minute buffer
        return now >= (expires_at - timedelta(minutes=5))
