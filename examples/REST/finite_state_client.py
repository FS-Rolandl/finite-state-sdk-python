#!/usr/bin/env python3

import aiohttp
import asyncio
from datetime import datetime
import logging
from typing import Optional, Dict, Any, List
import time

class RateLimiter:
    def __init__(self, max_requests_per_second: float = 10.0):
        self.max_requests = max_requests_per_second
        self.requests = []
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.time()
            # Remove requests older than 1 second
            self.requests = [req_time for req_time in self.requests if now - req_time < 1.0]
            
            if len(self.requests) >= self.max_requests:
                # Wait until we can make another request
                sleep_time = 1.0 - (now - self.requests[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                self.requests = self.requests[1:]
            
            self.requests.append(now)

class FiniteStateClient:
    def __init__(self, base_url: str, token: str, max_requests_per_second: float = 10.0):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.rate_limiter = RateLimiter(max_requests_per_second)
        self.session = None
        self.headers = {
            'X-Authorization': token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _make_request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
                          data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a request to the Finite State API."""
        url = f"{self.base_url}{path}"
        headers = {
            'X-Authorization': self.token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        print(f"\nMaking request to: {url}")
        print(f"Method: {method}")
        print(f"Params: {params}")
        print(f"Headers: {headers}")
        
        max_retries = 3
        retry_delay = 1  # Start with 1 second delay
        
        for attempt in range(max_retries):
            try:
                async with self.session.request(method, url, params=params, json=data, headers=headers) as response:
                    print(f"\nResponse status: {response.status}")
                    print(f"Response headers: {response.headers}")
                    
                    if response.status == 429:  # Rate limit exceeded
                        if attempt < max_retries - 1:  # Don't sleep on the last attempt
                            retry_after = int(response.headers.get('Retry-After', retry_delay))
                            print(f"Rate limit exceeded. Waiting {retry_after} seconds before retry...")
                            await asyncio.sleep(retry_after)
                            retry_delay *= 2  # Exponential backoff
                            continue
                    
                    response.raise_for_status()
                    return await response.json()
                    
            except aiohttp.ClientResponseError as e:
                if e.status == 429 and attempt < max_retries - 1:
                    retry_after = int(e.headers.get('Retry-After', retry_delay))
                    print(f"Rate limit exceeded. Waiting {retry_after} seconds before retry...")
                    await asyncio.sleep(retry_after)
                    retry_delay *= 2  # Exponential backoff
                    continue
                raise ValueError(f"API request failed: {str(e)}")
            except Exception as e:
                raise ValueError(f"API request failed: {str(e)}")
        
        raise ValueError("Rate limit exceeded")

    async def get_assets(self, start_date: Optional[datetime] = None, 
                        end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get all assets (projects) with optional date filtering."""
        params = {}
        if start_date:
            params['createdAtStart'] = start_date.isoformat()
        if end_date:
            params['createdAtEnd'] = end_date.isoformat()
        
        return await self._make_request('GET', '/api/public/v0/projects', params=params)

    async def get_asset_versions(self, branch_id: str, 
                               start_date: Optional[datetime] = None,
                               end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get versions for a specific branch with optional date filtering."""
        params = {}
        if start_date:
            params['createdAtStart'] = start_date.isoformat()
        if end_date:
            params['createdAtEnd'] = end_date.isoformat()
        
        return await self._make_request('GET', f'/api/public/v0/branches/{branch_id}/versions', params=params)

    async def get_findings(self, asset_version_id: str,
                          start_date: Optional[datetime] = None,
                          end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get findings for a specific asset version with optional date filtering."""
        params = {'assetVersionId': asset_version_id}
        if start_date:
            params['discoveredAtStart'] = start_date.isoformat()
        if end_date:
            params['discoveredAtEnd'] = end_date.isoformat()
        
        return await self._make_request('GET', '/api/public/v0/findings', params=params)

    async def get_risk_scores(self, asset_version_id: str,
                            start_date: Optional[datetime] = None,
                            end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Get risk scores for a specific asset version with optional date filtering."""
        params = {'assetVersionId': asset_version_id}
        if start_date:
            params['calculatedAtStart'] = start_date.isoformat()
        if end_date:
            params['calculatedAtEnd'] = end_date.isoformat()
        
        return await self._make_request('GET', '/api/public/v0/risk-scores', params=params)

    async def get_project_details(self, project_id: str) -> Dict[str, Any]:
        """Get details for a specific project."""
        return await self._make_request('GET', f'/api/public/v0/projects/{project_id}') 