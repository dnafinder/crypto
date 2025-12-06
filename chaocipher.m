function out=chaocipher(text,direction,varargin)
% CHAOCIPHER Encoder/Decoder
% The Chaocipher is a cipher method invented by J. F. Byrne in 1918 and
% described in his 1953 autobiographical *Silent Years*. He believed
% Chaocipher was simple, yet unbreakable and he offered cash rewards for
% anyone who could solve it. In May 2010 the Byrne family donated all
% Chaocipher-related papers and artifacts to the National Cryptologic
% Museum in Ft. Meade, Maryland, USA. This led to the disclosure of the
% Chaocipher algorithm.
%
% The Chaocipher system consists of two alphabets:
% - the "right" alphabet is used for locating the plaintext letter
% - the "left"  alphabet is used for reading the corresponding ciphertext
% After each letter is processed, both alphabets are permuted according to
% the Chaocipher rules, producing a dynamic substitution and high diffusion.
%
% All non A-Z characters are removed before processing.
%
% Syntax:
%   out=chaocipher(text,direction)
%   out=chaocipher(text,direction,la,ra)
%
% Input:
%   text      - Character array to encode or decode.
%   direction -  1 to encrypt
%               -1 to decrypt.
%   la        - Left alphabet: a scrambled 26-letter English alphabet.
%               If empty and direction is 1, the software will generate it.
%   ra        - Right alphabet: a scrambled 26-letter English alphabet.
%               If empty and direction is 1, the software will generate it.
%
% Output:
%   out - It is a structure:
%   out.plain     = the plain text (A-Z only)
%   out.encrypted = the coded text
%   out.la        = the used left alphabet
%   out.ra        = the used right alphabet
%
% Examples:
%
% la='HXUCZVAMDSLKPEFJRIGTWOBNYQ';
% ra='PTLNBQDEOYSFAVZKGJRIHWXUMC';
% out=chaocipher('Hide the gold into the tree stump',1,la,ra)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%            la: 'HXUCZVAMDSLKPEFJRIGTWOBNYQ'
%            ra: 'PTLNBQDEOYSFAVZKGJRIHWXUMC'
%     encrypted: 'WGZZNAXLHIBLVEIUIXYTLCTWSTT'
%
% out=chaocipher('WGZZNAXLHIBLVEIUIXYTLCTWSTT',-1,la,ra)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'WGZZNAXLHIBLVEIUIXYTLCTWSTT'
%            la: 'HXUCZVAMDSLKPEFJRIGTWOBNYQ'
%            ra: 'PTLNBQDEOYSFAVZKGJRIHWXUMC'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares,
% nihilist, playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'la',[], @(x) isempty(x) || (ischar(x) && numel(x)==26));
addOptional(p,'ra',[], @(x) isempty(x) || (ischar(x) && numel(x)==26));
parse(p,text,direction,varargin{:});
la = p.Results.la;
ra = p.Results.ra;
clear p

% If alphabets are empty:
% - decrypt is not allowed
% - encrypt will generate random permutations
if isempty(la)
    assert(direction==1,'This algorithm cannot decode without a left alphabet')
    la = char(randperm(26)+64);
else
    la = upper(la(:).'); % row vector
    assert(numel(la)==26,'Left alphabet must be 26 characters long')
    assert(all(la>='A' & la<='Z'),'Left alphabet must contain only A-Z letters')
    assert(numel(unique(la))==26,'Left alphabet must not contain duplicate letters')
end

if isempty(ra)
    assert(direction==1,'This algorithm cannot decode without a right alphabet')
    ra = char(randperm(26)+64);
else
    ra = upper(ra(:).'); % row vector
    assert(numel(ra)==26,'Right alphabet must be 26 characters long')
    assert(all(ra>='A' & ra<='Z'),'Right alphabet must contain only A-Z letters')
    assert(numel(unique(ra))==26,'Right alphabet must not contain duplicate letters')
end

% Preprocess text: keep only A-Z
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext = char(ctext);

switch direction
    case 1
        out.plain = ctext;
    case -1
        out.encrypted = ctext;
end
out.la = la;
out.ra = ra;

L = length(ctext);
texttmp = repmat(' ',1,L);

for I = 1:L
    switch direction
        case 1 % encrypt
            pos = find(ra==ctext(I),1,'first');
            texttmp(I) = la(pos);
        case -1 % decrypt
            pos = find(la==ctext(I),1,'first');
            texttmp(I) = ra(pos);
    end

    % Update left alphabet
    tmp = circshift(la,-pos+1);
    la = tmp([1 3:14 2 15:26]);

    % Update right alphabet
    tmp = circshift(ra,-pos);
    ra = tmp([1 2 4:14 3 15:26]);
end
clear tmp pos I L ctext la ra

switch direction
    case 1
        out.encrypted = texttmp;
    case -1
        out.plain = texttmp;
end
clear texttmp
end
