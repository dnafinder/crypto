function out=twintrifid(text,key,period1,period2,direction)
% TWINTRIFID Cipher encoder/decoder
% Wrapper that applies TRIFID twice with the same key cube.
%
% Encrypt:  C = TRIFID(TRIFID(P, key, period1), key, period2)
% Decrypt:  P = TRIFID(TRIFID(C, key, period2, -1), key, period1, -1)
%
% Output (minimal): out.plain, out.key, out.encrypted
%
% Example:
%
% out = twintrifid('Hide the gold into the tree stump','LEPRACHAUN',7,5,1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'LUYRBMMAIPNGPVKPOQLUQHVXLIO'
%
% >> out = twintrifid('LUYRBMMAIPNGPVKPOQLUQHVXLIO','LEPRACHAUN',7,5,-1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%     encrypted: 'LUYRBMMAIPNGPVKPOQLUQHVXLIO'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'period1',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'period2',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,period1,period2,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% Black box: store original key
out.key = key;

switch direction
    case 1
        a = trifid(text,key,period1,1);
        b = trifid(a.encrypted,key,period2,1);
        out.plain = a.plain;
        out.encrypted = b.encrypted;

    case -1
        a = trifid(text,key,period2,-1);
        b = trifid(a.plain,key,period1,-1);
        out.encrypted = a.encrypted;
        out.plain = b.plain;
end

end