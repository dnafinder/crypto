function out=nihilist2(text,key,direction)
% NIHILIST TRANSPOSITION Cipher encoder/decoder
% In the history of cryptography, the Nihilist cipher is a manually
% operated symmetric encryption cipher, originally used by Russian
% Nihilists in the 1880s to organize terrorism against the tsarist regime.
% The term is sometimes extended to several improved algorithms used much
% later for communication by the First Chief Directorate with its spies.
% A simpler form of the Nihilist was in double transposition.
% The plaintext is arranged into a square. Transpose columns by
% key order and then transpose rows. The ciphertext is taken off by rows.
%
% Syntax: 	out=nihilist2(text,key,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is the numeric array for transposition
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.encrypted = the coded text
%
% Examples:
%
% out=nihilist2('Hide the gold into the tree stump',[3 4 6 1 5 2],1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%           key: [3 4 6 1 5 2]
%     encrypted: 'INODT HET  TPUMDETH IE TRSE GLHOE'
%
% out=nihilist2('INODT HET  TPUMDETH IE TRSE GLHOE',[3 4 6 1 5 2],-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'INODT HET  TPUMDETH IE TRSE GLHOE'
%           key: [3 4 6 1 5 2]
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
% See also nihilist
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'},{'row','real','finite','nonnan','nonempty','integer','nonzero'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

if isstring(text)
    text = char(text);
end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

text = upper(text);

M = max(key);
assert(isequal(sort(key),1:1:M),'This key can not be used. Check it!')

LT = numel(text);
M2 = M^2;

assert(LT<=M2, ...
    'With this key you can encrypt a message of %i characters long.\nIndeed, your message is %i characters long', ...
    M2, LT)

% Prepare padding if needed (used in both branches)
if LT < M2
    RL = ceil(LT/M2);
    pad = repmat('§',1,RL*M2-LT);
else
    pad = '';
end

switch direction
    case 1 % encrypt
        if ~isempty(pad)
            ctext = reshape([text pad],M,M)';
        else
            ctext = reshape(text,M,M)';
        end

        ctext = ctext(:,key);
        ctext = ctext(key,:);

        ctext = regexprep(reshape(ctext',1,[]),'§','');

        out.plain = text;
        out.key = key;
        out.encrypted = ctext;

    case -1 % decrypt
        [~,Idx] = sort(key);

        ctext = repmat('^',M,M);

        I = M;
        padWork = pad;

        while ~isempty(padWork)
            Lp = numel(padWork);
            if Lp > M
                ctext(Idx(I),:) = repmat('§',1,M);
                padWork(1:M) = [];
                I = I - 1;
            else
                ctext(Idx(I),Idx(end-Lp+1:end)) = padWork;
                padWork = [];
            end
        end
        clear I Lp padWork

        tmp2 = text;

        for J = 1:M
            I = find(ctext(J,:)=='^');
            if ~isempty(I)
                Li = numel(I);
                ctext(J,I) = tmp2(1:Li);
                tmp2(1:Li) = [];
            end
        end
        clear I J Li tmp2

        ctext = ctext(Idx,:);
        ctext = ctext(:,Idx);
        clear Idx

        ctext = regexprep(reshape(ctext',1,[]),'§','');

        out.encrypted = text;
        out.key = key;
        out.plain = ctext;
end

clear ctext pad LT M M2
end
